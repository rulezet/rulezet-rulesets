rule TTP_XOR_MULT_DOSStub_3548 {
  strings:
    $key_3548 = { 61 20 [2] 15 38 [2] 52 3a [2] 15 2b [2] 5b 27 [2] 57 2d [2] 40 26 [2] 5b 68 [2] 66 }

  condition:
    any of them
}