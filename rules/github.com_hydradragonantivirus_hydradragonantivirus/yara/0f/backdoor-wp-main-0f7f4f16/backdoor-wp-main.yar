rule backdoor_wp_main {
  meta:
    description = "work1 - file backdoor_wp-main.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "6269e609deb8dace97457f319f20daddaf50e78767dde684984d9d70f129212b"

  strings:
    $x1  = "<?php error_reporting(E_ERROR|E_WARNING|E_PARSE|E_COMPILE_ERROR);ini_set('display_errors','on');set_time_limit(0);check_commands" ascii
    $s2  = "90cb14);$wny04d597606e0989a6=execute_query(\"UPDATE \".$wid727bb92f57c3951d.\"posts SET post_content = '$kmi72f67a08bb51167e' WH" ascii
    $s3  = "f0f862b0c65d1b8=execute_query(\"INSERT INTO \".$wid727bb92f57c3951d.\"posts (`post_title`, `post_content`, `post_status`, `post_" ascii
    $s4  = "=execute_query(\"SELECT id,guid,post_content FROM \".$wid727bb92f57c3951d.\"posts WHERE id = $drie5a9d8684a8edfed\");$rvu3f0f862" ascii
    $s5  = "8){echo\"Failed to execute query ($eipe0af5865757b3f2a): \".get_error();die;}return $rvu3f0f862b0c65d1b8;}function get_error(){g" ascii
    $s6  = "05039f7a65);dispatch_exec_commands_for_conf();}function config_parse_insert_post(){list($slz87de66479aea0306,$sto2040a28d572e088" ascii
    $s7  = "'login',$lgc518fd46dddb3f97e[array_rand($lgc518fd46dddb3f97e)]);return $vgta455620d6612d981->$ovpbbf2466e744a5003;}function get_" ascii
    $s8  = "6df5bde;global $wid727bb92f57c3951d;$rvu3f0f862b0c65d1b8=execute_query(\"SELECT id FROM \".$wid727bb92f57c3951d.\"posts WHERE po" ascii
    $s9  = "a93a176df5bde;}function get_first_post_id(){global $wid727bb92f57c3951d;$rvu3f0f862b0c65d1b8=execute_query(\"SELECT id FROM \".$" ascii
    $s10 = "atch_exec_commands_for_conf(){if(array_key_exists('first',$_REQUEST)){get_posts_count();$gsc3caa85db42b2089e=get_first_post_id()" ascii
    $s11 = "<?php error_reporting(E_ERROR|E_WARNING|E_PARSE|E_COMPILE_ERROR);ini_set('display_errors','on');set_time_limit(0);check_commands" ascii
    $s12 = "nect_using_parse_config($rao5b668e57ec706744){global $wid727bb92f57c3951d;$ibua1a4b0b8357dda28=file_get_contents($rao5b668e57ec7" ascii
    $s13 = "c3951d=$bqo9b80b13ee7aa2867;$gkn531a93a176df5bde=db_connect(DB_HOST,DB_USER,DB_PASSWORD,DB_NAME,'require');return $gkn531a93a176" ascii
    $s14 = "7016 password: $jwp8db64bce186cbad8 name: $lewfb507393460e685e method_name: $cluc49cf36844cf3448#\\n\";if(is_mysqli()){$rij1b9aa" ascii
    $s15 = "){print\"#Next id: $mrbefabc30264bfc793#\\n\";}else{print\"#No next id#\\n\";}}function check_commands(){if(array_key_exists('de" ascii
    $s16 = "nk')){print\"#loaded wp-load#\\n\";wp_load_insert_post();}else{print\"#Failed to load wp-load, trying to parse config directly#" ascii
    $s17 = "conf_path(){return get_file_path('wp-config.php');}function get_load_path(){return get_file_path('wp-load.php');}function get_fi" ascii
    $s18 = "a3ff8e5c2997);echo\"#Failed: $utx019af902730a88c4#\\n\";}}?>" fullword ascii
    $s19 = "ts_count(){global $wid727bb92f57c3951d;echo\"#wp_prefix: $wid727bb92f57c3951d#\\n\";$rvu3f0f862b0c65d1b8=execute_query(\"SELECT " ascii
    $s20 = "3['pinged'].\"','\".$axnab690da061c9b963['post_content_filtered'].\"')\");return $gkn531a93a176df5bde->$unn8916879d1cfb675c;}fun" ascii

  condition:
    (uint16(0) == 0x3c0a and
      filesize < 40KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}