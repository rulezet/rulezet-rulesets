rule TTP_XOR_MULT_DOSStub_4556 {
  strings:
    $key_4556 = { 11 3e [2] 65 26 [2] 22 24 [2] 65 35 [2] 2b 39 [2] 27 33 [2] 30 38 [2] 2b 76 [2] 16 }

  condition:
    any of them
}