rule TTP_XOR_MULT_DOSStub_e054 {
  strings:
    $key_e054 = { b4 3c [2] c0 24 [2] 87 26 [2] c0 37 [2] 8e 3b [2] 82 31 [2] 95 3a [2] 8e 74 [2] b3 }

  condition:
    any of them
}