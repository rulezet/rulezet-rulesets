rule TTP_XOR_MULT_DOSStub_4545 {
  strings:
    $key_4545 = { 11 2d [2] 65 35 [2] 22 37 [2] 65 26 [2] 2b 2a [2] 27 20 [2] 30 2b [2] 2b 65 [2] 16 }

  condition:
    any of them
}