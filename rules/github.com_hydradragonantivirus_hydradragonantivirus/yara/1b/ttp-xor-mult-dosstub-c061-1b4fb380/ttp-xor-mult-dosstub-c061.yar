rule TTP_XOR_MULT_DOSStub_c061 {
  strings:
    $key_c061 = { 94 09 [2] e0 11 [2] a7 13 [2] e0 02 [2] ae 0e [2] a2 04 [2] b5 0f [2] ae 41 [2] 93 }

  condition:
    any of them
}