rule TTP_XOR_MULT_DOSStub_d6e2 {
  strings:
    $key_d6e2 = { 82 8a [2] f6 92 [2] b1 90 [2] f6 81 [2] b8 8d [2] b4 87 [2] a3 8c [2] b8 c2 [2] 85 }

  condition:
    any of them
}