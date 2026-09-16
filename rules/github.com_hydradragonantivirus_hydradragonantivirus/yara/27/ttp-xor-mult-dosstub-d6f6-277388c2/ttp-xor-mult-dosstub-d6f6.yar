rule TTP_XOR_MULT_DOSStub_d6f6 {
  strings:
    $key_d6f6 = { 82 9e [2] f6 86 [2] b1 84 [2] f6 95 [2] b8 99 [2] b4 93 [2] a3 98 [2] b8 d6 [2] 85 }

  condition:
    any of them
}