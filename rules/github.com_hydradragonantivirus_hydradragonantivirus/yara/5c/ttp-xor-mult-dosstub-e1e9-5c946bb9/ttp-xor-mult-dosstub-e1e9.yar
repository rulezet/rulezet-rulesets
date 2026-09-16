rule TTP_XOR_MULT_DOSStub_e1e9 {
  strings:
    $key_e1e9 = { b5 81 [2] c1 99 [2] 86 9b [2] c1 8a [2] 8f 86 [2] 83 8c [2] 94 87 [2] 8f c9 [2] b2 }

  condition:
    any of them
}