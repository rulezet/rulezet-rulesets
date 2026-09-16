rule TTP_XOR_MULT_DOSStub_4315 {
  strings:
    $key_4315 = { 17 7d [2] 63 65 [2] 24 67 [2] 63 76 [2] 2d 7a [2] 21 70 [2] 36 7b [2] 2d 35 [2] 10 }

  condition:
    any of them
}