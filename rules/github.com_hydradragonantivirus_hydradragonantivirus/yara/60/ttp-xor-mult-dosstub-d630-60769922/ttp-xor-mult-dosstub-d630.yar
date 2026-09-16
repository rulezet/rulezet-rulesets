rule TTP_XOR_MULT_DOSStub_d630 {
  strings:
    $key_d630 = { 82 58 [2] f6 40 [2] b1 42 [2] f6 53 [2] b8 5f [2] b4 55 [2] a3 5e [2] b8 10 [2] 85 }

  condition:
    any of them
}