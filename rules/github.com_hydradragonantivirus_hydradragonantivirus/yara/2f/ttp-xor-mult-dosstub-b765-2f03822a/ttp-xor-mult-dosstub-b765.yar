rule TTP_XOR_MULT_DOSStub_b765 {
  strings:
    $key_b765 = { e3 0d [2] 97 15 [2] d0 17 [2] 97 06 [2] d9 0a [2] d5 00 [2] c2 0b [2] d9 45 [2] e4 }

  condition:
    any of them
}