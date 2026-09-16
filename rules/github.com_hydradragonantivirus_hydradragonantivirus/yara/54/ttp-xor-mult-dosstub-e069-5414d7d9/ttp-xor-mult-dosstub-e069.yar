rule TTP_XOR_MULT_DOSStub_e069 {
  strings:
    $key_e069 = { b4 01 [2] c0 19 [2] 87 1b [2] c0 0a [2] 8e 06 [2] 82 0c [2] 95 07 [2] 8e 49 [2] b3 }

  condition:
    any of them
}