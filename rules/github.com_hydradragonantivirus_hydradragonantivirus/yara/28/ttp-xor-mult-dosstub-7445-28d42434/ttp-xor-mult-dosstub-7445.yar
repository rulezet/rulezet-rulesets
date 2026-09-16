rule TTP_XOR_MULT_DOSStub_7445 {
  strings:
    $key_7445 = { 20 2d [2] 54 35 [2] 13 37 [2] 54 26 [2] 1a 2a [2] 16 20 [2] 01 2b [2] 1a 65 [2] 27 }

  condition:
    any of them
}