rule TTP_XOR_MULT_DOSStub_e665 {
  strings:
    $key_e665 = { b2 0d [2] c6 15 [2] 81 17 [2] c6 06 [2] 88 0a [2] 84 00 [2] 93 0b [2] 88 45 [2] b5 }

  condition:
    any of them
}