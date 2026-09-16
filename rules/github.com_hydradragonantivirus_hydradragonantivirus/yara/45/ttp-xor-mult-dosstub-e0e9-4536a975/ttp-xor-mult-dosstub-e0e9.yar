rule TTP_XOR_MULT_DOSStub_e0e9 {
  strings:
    $key_e0e9 = { b4 81 [2] c0 99 [2] 87 9b [2] c0 8a [2] 8e 86 [2] 82 8c [2] 95 87 [2] 8e c9 [2] b3 }

  condition:
    any of them
}