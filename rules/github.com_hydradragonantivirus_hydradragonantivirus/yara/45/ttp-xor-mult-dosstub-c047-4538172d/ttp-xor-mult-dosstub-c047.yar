rule TTP_XOR_MULT_DOSStub_c047 {
  strings:
    $key_c047 = { 94 2f [2] e0 37 [2] a7 35 [2] e0 24 [2] ae 28 [2] a2 22 [2] b5 29 [2] ae 67 [2] 93 }

  condition:
    any of them
}