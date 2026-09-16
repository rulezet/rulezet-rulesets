rule TTP_XOR_MULT_DOSStub_b772 {
  strings:
    $key_b772 = { e3 1a [2] 97 02 [2] d0 00 [2] 97 11 [2] d9 1d [2] d5 17 [2] c2 1c [2] d9 52 [2] e4 }

  condition:
    any of them
}