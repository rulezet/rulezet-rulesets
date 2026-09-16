rule TTP_XOR_MULT_DOSStub_d6e1 {
  strings:
    $key_d6e1 = { 82 89 [2] f6 91 [2] b1 93 [2] f6 82 [2] b8 8e [2] b4 84 [2] a3 8f [2] b8 c1 [2] 85 }

  condition:
    any of them
}