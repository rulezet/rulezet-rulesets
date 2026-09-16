rule TTP_XOR_MULT_DOSStub_4323 {
  strings:
    $key_4323 = { 17 4b [2] 63 53 [2] 24 51 [2] 63 40 [2] 2d 4c [2] 21 46 [2] 36 4d [2] 2d 03 [2] 10 }

  condition:
    any of them
}