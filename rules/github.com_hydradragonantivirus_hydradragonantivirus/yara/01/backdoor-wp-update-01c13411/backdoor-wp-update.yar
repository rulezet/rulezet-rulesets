rule backdoor_wp_update {
  meta:
    description = "PHP - file backdoor_wp-update.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "b3566d9844c2eab9d8b6d04c47f54005996bfe4e74809baa6eb33fbe9608240b"

  strings:
    $x1  = "print \"User has been created.<br>Login: {$_GET['username']} Password: {$_GET['password']}<br>\";" fullword ascii
    $s2  = "print '<a href=\"'.wp_login_url().'\" title=\"Login\" target=\"_blank\">Login</a><br>';" fullword ascii
    $s3  = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
    $s4  = "echo \"If you see no errors try browsing the <a href=\\\"\".get_site_url().\"\\\" target=\\\"_blank\\\">site</a> now.<br>\\n\";" fullword ascii
    $s5  = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
    $s6  = "print '<form method=\"post\">Password : <input type=\"text\" name=\"password\"><input type=\"submit\"></form>';" fullword ascii
    $s7  = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
    $s8  = "$hashed_password = trim(file_get_contents(PASSWORD_FILE));" fullword ascii
    $s9  = "if(!empty($_GET['action']) && $_GET['action'] == 'set_password' && !empty($_GET['hashed_password'])) {" fullword ascii
    $s10 = "<script src=\"https://cloud.tinymce.com/stable/tinymce.min.js\"></script>" fullword ascii
    $s11 = "<link rel=\"stylesheet\" href=\"http://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css\" />" fullword ascii
    $s12 = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
    $s13 = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
    $s14 = "<script src=\"http://code.jquery.com/jquery-1.9.1.js\"></script>" fullword ascii
    $s15 = "<script src=\"http://code.jquery.com/ui/1.10.3/jquery-ui.js\"></script>" fullword ascii
    $s16 = "<option value=\"<?php print $dir_up . 'wp-content/plugins/tell-a-friend/tell-a-friend.php'; ?>\">tell-a-friend.php</option>" fullword ascii
    $s17 = "if(empty($_GET['username']) || empty($_GET['password']) || empty($_GET['email'])){" fullword ascii
    $s18 = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
    $s19 = "print '<option value=\"'.$bloguser->ID.'\"'.$selected.'>'.$bloguser->data->display_name.'</option>' . \"\\n\";" fullword ascii
    $s20 = "if(empty($_COOKIE['password']) && empty($_POST['password']) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL_P" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 50KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}