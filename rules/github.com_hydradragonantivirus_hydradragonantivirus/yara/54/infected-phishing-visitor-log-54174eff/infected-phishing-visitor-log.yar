rule infected_phishing_visitor_log {
  meta:
    description = "phishing - file visitor_log.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "4a78aef191ca6b029c8aa815d21924e7ce856c2cc5823c743a399b0cff6b7c37"

  strings:
    $s1 = "fputs($fp, \"IP: $v_ip - DATE: $v_date - BROWSER: $v_agent\\r\\n\");" fullword ascii
    $s2 = "$fp = fopen(\"logs/ips.txt\", \"a\");" fullword ascii
    $s3 = "$v_agent = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
    $s4 = "Created by legzy -- icq: 692561824 " fullword ascii
    $s5 = "$v_ip = $_SERVER['REMOTE_ADDR'];" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}