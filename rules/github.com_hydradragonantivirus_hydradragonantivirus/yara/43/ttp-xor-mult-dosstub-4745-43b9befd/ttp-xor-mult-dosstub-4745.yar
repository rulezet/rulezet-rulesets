rule TTP_XOR_MULT_DOSStub_4745 {
  strings:
    $key_4745 = { 13 2d [2] 67 35 [2] 20 37 [2] 67 26 [2] 29 2a [2] 25 20 [2] 32 2b [2] 29 65 [2] 14 }

  condition:
    any of them
}