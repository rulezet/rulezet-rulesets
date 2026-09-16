rule TTP_XOR_MULT_DOSStub_e074 {
  strings:
    $key_e074 = { b4 1c [2] c0 04 [2] 87 06 [2] c0 17 [2] 8e 1b [2] 82 11 [2] 95 1a [2] 8e 54 [2] b3 }

  condition:
    any of them
}