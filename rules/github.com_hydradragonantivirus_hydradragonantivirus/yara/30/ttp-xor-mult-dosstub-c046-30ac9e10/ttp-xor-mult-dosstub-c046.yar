rule TTP_XOR_MULT_DOSStub_c046 {
  strings:
    $key_c046 = { 94 2e [2] e0 36 [2] a7 34 [2] e0 25 [2] ae 29 [2] a2 23 [2] b5 28 [2] ae 66 [2] 93 }

  condition:
    any of them
}