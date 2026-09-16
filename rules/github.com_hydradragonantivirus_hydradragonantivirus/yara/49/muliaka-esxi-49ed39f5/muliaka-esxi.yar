rule Muliaka_ESXi {
  meta:
    author      = "rivitna"
    family      = "ransomware.muliaka.esxi"
    description = "Muliaka ransomware ESXi"
    severity    = 10
    score       = 100

  strings:
    $s0 = "crypt_file_one" ascii
    $s1 = "crypt_file_two" ascii
    $s2 = "visit_dirs_two" ascii
    $s3 = "valid_file_one" ascii
    $s4 = "Send an email to " ascii
    $s5 = {
      48 B8 24 24 24 24 24 24 24 24 48 89 84 24 ?? 0? 00 00
      48 89 84 24
    }

  condition:
    (uint32(0) == 0x464C457F) and
    (
      (4 of ($s*))
    )
}