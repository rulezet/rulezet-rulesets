rule _backdoor_wp_code_backdoor_wp_update_0 {
  meta:
    description = "PHP - from files backdoor_wp_code.php, backdoor_wp-update.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "de94bbc0d4fca3b778c6fad1a7719c8aacce8e464be65864e41abefc0326ac6f"
    hash2       = "b3566d9844c2eab9d8b6d04c47f54005996bfe4e74809baa6eb33fbe9608240b"

  strings:
    $s1  = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
    $s2  = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
    $s3  = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
    $s4  = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
    $s5  = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
    $s6  = "Author URI: http://www.freetellafriend.com/" fullword ascii
    $s7  = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
    $s8  = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
    $s9  = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
    $s10 = "se;\" target=\"_blank\" title=\"Share This Post\"><img src=\"\\'.$taf_img.\\'\" style=\"width:127px;height:16px;border:0px;\" al" ascii
    $s11 = "is Post\" title=\"Share This Post\" /></a>\\';" fullword ascii
    $s12 = "n(\\'https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\\', \\'freetellafriend\\', \\'scro" ascii
    $s13 = "if(!empty($my_posts[0]->ID) && is_numeric($my_posts[0]->ID)) {" fullword ascii
    $s14 = "$taf_permlink = urlencode(get_permalink($post->ID));" fullword ascii
    $s15 = "$taf_title = urlencode(get_the_title($post->ID) );" fullword ascii
    $s16 = "include_once( $dir_up . 'wp-admin/includes/class-ftp.php');" fullword ascii
    $s17 = "add_filter(\\'the_content\\', \\'tell_a_friend\\');" fullword ascii
    $s18 = "include_once( $dir_up . 'wp-admin/includes/screen.php');" fullword ascii
    $s19 = "include_once( $dir_up . 'wp-admin/includes/update.php');" fullword ascii
    $s20 = "include_once( $dir_up . 'wp-admin/includes/plugin.php');" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 50KB and (8 of them)
    ) or (all of them)
}