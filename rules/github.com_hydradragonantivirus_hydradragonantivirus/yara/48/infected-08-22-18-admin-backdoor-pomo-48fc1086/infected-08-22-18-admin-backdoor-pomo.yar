rule infected_08_22_18_admin_backdoor_pomo {
  meta:
    description = "shell5 - file pomo.php3"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-23"
    hash1       = "6f986483b7dbfb173bb3744c19a839d793dd53248e09b9da63906f9e3e1fbb7b"

  strings:
    $s1  = "wp_redirect(get_bloginfo('wpurl') . '/wp-admin');" fullword ascii
    $s2  = "wp_set_current_user($user_id, $user_login);" fullword ascii
    $s3  = "echo \"You are logged in as $user_login\";" fullword ascii
    $s4  = "do_action('wp_login', $user_login);" fullword ascii
    $s5  = "$user_login = $user_info->user_login;" fullword ascii
    $s6  = "$user_ids = $wpdb->get_results($query_str);" fullword ascii
    $s7  = "$query_str = \"SELECT ID FROM $wpdb->users\";" fullword ascii
    $s8  = "require('../../wp-blog-header.php');" fullword ascii
    $s9  = "$user_info = get_userdata($user_id);" fullword ascii
    $s10 = "if (function_exists('get_admin_url')) {" fullword ascii
    $s11 = "wp_redirect(get_admin_url());" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}