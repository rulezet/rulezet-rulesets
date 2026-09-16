rule TTP_XOR_MULT_DOSStub_c077 {
  strings:
    $key_c077 = { 94 1f [2] e0 07 [2] a7 05 [2] e0 14 [2] ae 18 [2] a2 12 [2] b5 19 [2] ae 57 [2] 93 }

  condition:
    any of them
}