rule TTP_XOR_MULT_DOSStub_3145 {
  strings:
    $key_3145 = { 65 2d [2] 11 35 [2] 56 37 [2] 11 26 [2] 5f 2a [2] 53 20 [2] 44 2b [2] 5f 65 [2] 62 }

  condition:
    any of them
}