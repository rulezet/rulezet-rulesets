rule TTP_XOR_MULT_DOSStub_e024 {
  strings:
    $key_e024 = { b4 4c [2] c0 54 [2] 87 56 [2] c0 47 [2] 8e 4b [2] 82 41 [2] 95 4a [2] 8e 04 [2] b3 }

  condition:
    any of them
}