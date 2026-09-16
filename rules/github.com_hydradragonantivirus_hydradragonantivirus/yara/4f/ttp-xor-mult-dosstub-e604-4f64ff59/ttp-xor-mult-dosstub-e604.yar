rule TTP_XOR_MULT_DOSStub_e604 {
  strings:
    $key_e604 = { b2 6c [2] c6 74 [2] 81 76 [2] c6 67 [2] 88 6b [2] 84 61 [2] 93 6a [2] 88 24 [2] b5 }

  condition:
    any of them
}