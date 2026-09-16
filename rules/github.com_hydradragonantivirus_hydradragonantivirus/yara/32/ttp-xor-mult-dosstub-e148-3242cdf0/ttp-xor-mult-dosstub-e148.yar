rule TTP_XOR_MULT_DOSStub_e148 {
  strings:
    $key_e148 = { b5 20 [2] c1 38 [2] 86 3a [2] c1 2b [2] 8f 27 [2] 83 2d [2] 94 26 [2] 8f 68 [2] b2 }

  condition:
    any of them
}