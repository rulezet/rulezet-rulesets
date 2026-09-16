rule TTP_XOR_MULT_DOSStub_d670 {
  strings:
    $key_d670 = { 82 18 [2] f6 00 [2] b1 02 [2] f6 13 [2] b8 1f [2] b4 15 [2] a3 1e [2] b8 50 [2] 85 }

  condition:
    any of them
}