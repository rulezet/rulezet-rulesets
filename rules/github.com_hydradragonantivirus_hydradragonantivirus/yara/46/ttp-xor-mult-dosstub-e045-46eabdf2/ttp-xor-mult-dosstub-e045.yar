rule TTP_XOR_MULT_DOSStub_e045 {
  strings:
    $key_e045 = { b4 2d [2] c0 35 [2] 87 37 [2] c0 26 [2] 8e 2a [2] 82 20 [2] 95 2b [2] 8e 65 [2] b3 }

  condition:
    any of them
}