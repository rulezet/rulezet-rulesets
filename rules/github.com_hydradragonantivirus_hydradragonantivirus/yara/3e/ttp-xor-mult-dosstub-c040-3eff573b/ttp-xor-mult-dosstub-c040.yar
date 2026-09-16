rule TTP_XOR_MULT_DOSStub_c040 {
  strings:
    $key_c040 = { 94 28 [2] e0 30 [2] a7 32 [2] e0 23 [2] ae 2f [2] a2 25 [2] b5 2e [2] ae 60 [2] 93 }

  condition:
    any of them
}