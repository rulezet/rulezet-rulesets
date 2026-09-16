rule TTP_XOR_MULT_DOSStub_4145 {
  strings:
    $key_4145 = { 15 2d [2] 61 35 [2] 26 37 [2] 61 26 [2] 2f 2a [2] 23 20 [2] 34 2b [2] 2f 65 [2] 12 }

  condition:
    any of them
}