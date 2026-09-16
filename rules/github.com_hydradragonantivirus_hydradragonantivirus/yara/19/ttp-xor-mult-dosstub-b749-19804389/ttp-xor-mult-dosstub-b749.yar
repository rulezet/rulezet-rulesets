rule TTP_XOR_MULT_DOSStub_b749 {
  strings:
    $key_b749 = { e3 21 [2] 97 39 [2] d0 3b [2] 97 2a [2] d9 26 [2] d5 2c [2] c2 27 [2] d9 69 [2] e4 }

  condition:
    any of them
}