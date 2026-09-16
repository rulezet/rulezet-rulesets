rule TTP_XOR_MULT_DOSStub_d620 {
  strings:
    $key_d620 = { 82 48 [2] f6 50 [2] b1 52 [2] f6 43 [2] b8 4f [2] b4 45 [2] a3 4e [2] b8 00 [2] 85 }

  condition:
    any of them
}