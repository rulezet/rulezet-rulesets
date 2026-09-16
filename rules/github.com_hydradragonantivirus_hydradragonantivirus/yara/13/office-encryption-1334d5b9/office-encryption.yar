rule office_encryption {
  meta:
    author = "@tylabs"
    date   = "2015 06 22"

  strings:
    $sig1  = "Microsoft Base Cryptography Provider v" wide
    $sig2  = "EncryptedSummary" wide
    $magic = { D0 CF 11 E0 }

  condition:
    ($magic at 0) and (1 of ($sig*))

}