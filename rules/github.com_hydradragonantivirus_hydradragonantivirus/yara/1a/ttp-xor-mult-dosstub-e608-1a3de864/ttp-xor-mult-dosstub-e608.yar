rule TTP_XOR_MULT_DOSStub_e608 {
  strings:
    $key_e608 = { b2 60 [2] c6 78 [2] 81 7a [2] c6 6b [2] 88 67 [2] 84 6d [2] 93 66 [2] 88 28 [2] b5 }

  condition:
    any of them
}