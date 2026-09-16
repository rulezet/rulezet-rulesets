rule TTP_XOR_MULT_DOSStub_e617 {
  strings:
    $key_e617 = { b2 7f [2] c6 67 [2] 81 65 [2] c6 74 [2] 88 78 [2] 84 72 [2] 93 79 [2] 88 37 [2] b5 }

  condition:
    any of them
}