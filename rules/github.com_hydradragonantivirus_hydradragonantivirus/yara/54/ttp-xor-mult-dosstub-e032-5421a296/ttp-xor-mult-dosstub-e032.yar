rule TTP_XOR_MULT_DOSStub_e032 {
  strings:
    $key_e032 = { b4 5a [2] c0 42 [2] 87 40 [2] c0 51 [2] 8e 5d [2] 82 57 [2] 95 5c [2] 8e 12 [2] b3 }

  condition:
    any of them
}