rule TTP_XOR_MULT_DOSStub_e034 {
  strings:
    $key_e034 = { b4 5c [2] c0 44 [2] 87 46 [2] c0 57 [2] 8e 5b [2] 82 51 [2] 95 5a [2] 8e 14 [2] b3 }

  condition:
    any of them
}