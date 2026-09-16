rule TTP_XOR_MULT_DOSStub_d6e4 {
  strings:
    $key_d6e4 = { 82 8c [2] f6 94 [2] b1 96 [2] f6 87 [2] b8 8b [2] b4 81 [2] a3 8a [2] b8 c4 [2] 85 }

  condition:
    any of them
}