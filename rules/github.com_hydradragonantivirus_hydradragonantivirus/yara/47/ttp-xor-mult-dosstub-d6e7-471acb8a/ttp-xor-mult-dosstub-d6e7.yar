rule TTP_XOR_MULT_DOSStub_d6e7 {
  strings:
    $key_d6e7 = { 82 8f [2] f6 97 [2] b1 95 [2] f6 84 [2] b8 88 [2] b4 82 [2] a3 89 [2] b8 c7 [2] 85 }

  condition:
    any of them
}