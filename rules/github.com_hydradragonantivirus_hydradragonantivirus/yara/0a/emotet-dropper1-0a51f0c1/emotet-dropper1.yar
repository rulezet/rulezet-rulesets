rule emotet_dropper1 {
  meta:
    description = "03-01-19 - file emotet-dropper1.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-03-01"
    hash1       = "0311b2d34851ab3ba7f9f1ecd77a3bf0effbd52e8d4d2c20e30f9719bb7dcb9c"

  strings:
    $s1 = "6576616c28677a696e666c617465286261736536345f6465636f64652822" ascii  
    $s2 = "222929293b" ascii  
    $s3 = "$n5c62c1bcb81d1 = fn5c62c1bcb819b('6576616c28677a696e666c617465286261736536345f6465636f64652822');" fullword ascii
    $s4 = "eval($n5c62c1bcb81d1" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}