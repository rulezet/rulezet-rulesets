rule TTP_XOR_MULT_DOSStub_e009 {
  strings:
    $key_e009 = { b4 61 [2] c0 79 [2] 87 7b [2] c0 6a [2] 8e 66 [2] 82 6c [2] 95 67 [2] 8e 29 [2] b3 }

  condition:
    any of them
}