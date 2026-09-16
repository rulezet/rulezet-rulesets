rule TTP_XOR_MULT_DOSStub_e574 {
  strings:
    $key_e574 = { b1 1c [2] c5 04 [2] 82 06 [2] c5 17 [2] 8b 1b [2] 87 11 [2] 90 1a [2] 8b 54 [2] b6 }

  condition:
    any of them
}