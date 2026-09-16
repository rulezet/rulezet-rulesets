rule TTP_XOR_MULT_DOSStub_1545 {
  strings:
    $key_1545 = { 41 2d [2] 35 35 [2] 72 37 [2] 35 26 [2] 7b 2a [2] 77 20 [2] 60 2b [2] 7b 65 [2] 46 }

  condition:
    any of them
}