rule TTP_XOR_MULT_DOSStub_d646 {
  strings:
    $key_d646 = { 82 2e [2] f6 36 [2] b1 34 [2] f6 25 [2] b8 29 [2] b4 23 [2] a3 28 [2] b8 66 [2] 85 }

  condition:
    any of them
}