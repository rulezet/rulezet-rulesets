rule TTP_XOR_MULT_DOSStub_e5e4 {
  strings:
    $key_e5e4 = { b1 8c [2] c5 94 [2] 82 96 [2] c5 87 [2] 8b 8b [2] 87 81 [2] 90 8a [2] 8b c4 [2] b6 }

  condition:
    any of them
}