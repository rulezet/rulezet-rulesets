rule TTP_XOR_MULT_DOSStub_4308 {
  strings:
    $key_4308 = { 17 60 [2] 63 78 [2] 24 7a [2] 63 6b [2] 2d 67 [2] 21 6d [2] 36 66 [2] 2d 28 [2] 10 }

  condition:
    any of them
}