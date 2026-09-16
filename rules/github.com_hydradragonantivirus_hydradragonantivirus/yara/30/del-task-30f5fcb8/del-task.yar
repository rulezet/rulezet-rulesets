rule del_task {
  meta:
    description = "amadey-botnet - file del_task.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "e58ce2a8fbc9ca9dc4fb34233b2d4a87fd155f03a320f0861fcde3b32eb057c5"

  strings:
    $s1  = "header( \"Location: login.php\" );" fullword ascii
    $s2  = "mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ); " fullword ascii
    $s3  = "mysql_query( \"DELETE FROM tasks_exec WHERE task_id = '$id'\" );" fullword ascii
    $s4  = "echo \"Please login at root, observers cant delete task\"; " fullword ascii
    $s5  = "header( \"Refresh: 1; url = show_tasks.php\" );" fullword ascii
    $s6  = "include( \"header.php\" );" fullword ascii
    $s7  = "header( \"Location: \" . $_SERVER['HTTP_REFERER'] . \"\" );" fullword ascii
    $s8  = "if ( $_SESSION['Name'] == \"ROOT\" )  " fullword ascii
    $s9  = "include( \"cfg/config.php\" ); " fullword ascii
    $s10 = "if ( !is_numeric( $_GET['id'] ) ) " fullword ascii
    $s11 = "$id = strfix( $_GET['id'] );" fullword ascii
    $s12 = "if ( !( isset( $_SESSION['Name'] ) ) )" fullword ascii
    $s13 = "mysql_query( \"DELETE FROM tasks WHERE id = '$id' LIMIT 1\" );" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}