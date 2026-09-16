rule TTP_XOR_MULT_DOSStub_c0e6 {
  strings:
    $key_c0e6 = { 94 8e [2] e0 96 [2] a7 94 [2] e0 85 [2] ae 89 [2] a2 83 [2] b5 88 [2] ae c6 [2] 93 }

  condition:
    any of them
}