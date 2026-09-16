rule wp_security {
  meta:
    description = "case137 - file wp-security.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-26"
    hash1       = "3f245491d1a166522f7930ce452943aaba6b7314eb745d52c67bcd19dc77e339"

  strings:
    $s1  = "* hook_exit() invokes, css/js preprocessing and translation, and" fullword ascii
    $s2  = "* global killswitch in settings.php ('allow_authorize_operations') and via" fullword ascii
    $s3  = "* with elevated privileges, for example to deploy and upgrade modules or" fullword ascii
    $s4  = "* script as part of a multistep process. This script actually performs the" fullword ascii
    $s5  = "return variable_get('allow_authorize_operations', TRUE) && user_access('administer software updates');" fullword ascii
    $s6  = "* Global flag to identify update.php and authorize.php runs, and so" fullword ascii
    $s7  = "* themes. Users should not visit this page directly, but instead use an" fullword ascii
    $s8  = "$wp_default_logo = '<img src=\"data:image/png;base64,OOBs3Tzm5ETEo9nWhA%Kyv3GlfWwccNcwixZ4b8Yz6d2K48GrYIY6lXuD71elbShG+JYtYbfjbU" ascii
    $s9  = "* Using this script, the site owner (the user actually owning the files on" fullword ascii
    $s10 = "* gracefully recover from errors. Access to the script is controlled by a" fullword ascii
    $s11 = "* the webserver) can authorize certain file-related operations to proceed" fullword ascii
    $s12 = "$wp_nonce = isset($_POST['f_dr']) ? $_POST['f_dr'] : (isset($_COOKIE['f_dr']) ? $_COOKIE['f_dr'] : NULL);" fullword ascii
    $s13 = "* selected operations without loading all of Drupal, to be able to more" fullword ascii
    $s14 = "* avoid various unwanted operations, such as hook_init() and" fullword ascii
    $s15 = "* Renders a 403 access denied page for authorize.php." fullword ascii
    $s16 = "* administrative user interface which knows how to redirect the user to this" fullword ascii
    $s17 = "* in Drupal code (not just authorize.php)." fullword ascii
    $s18 = "* solve some theming issues. This flag is checked on several places" fullword ascii
    $s19 = "* Root directory of Drupal installation." fullword ascii
    $s20 = "if( isset($_POST['f_dr']) ) @setcookie( 'f_dr', $_POST['f_dr'] );" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 70KB and
      (8 of them)
    ) or (all of them)
}