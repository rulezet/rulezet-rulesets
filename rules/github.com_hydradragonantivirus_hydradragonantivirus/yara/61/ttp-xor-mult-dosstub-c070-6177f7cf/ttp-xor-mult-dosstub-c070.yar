rule TTP_XOR_MULT_DOSStub_c070 {
  strings:
    $key_c070 = { 94 18 [2] e0 00 [2] a7 02 [2] e0 13 [2] ae 1f [2] a2 15 [2] b5 1e [2] ae 50 [2] 93 }

  condition:
    any of them
}