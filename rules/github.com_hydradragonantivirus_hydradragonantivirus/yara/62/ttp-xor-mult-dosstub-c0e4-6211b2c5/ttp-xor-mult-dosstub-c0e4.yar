rule TTP_XOR_MULT_DOSStub_c0e4 {
  strings:
    $key_c0e4 = { 94 8c [2] e0 94 [2] a7 96 [2] e0 87 [2] ae 8b [2] a2 81 [2] b5 8a [2] ae c4 [2] 93 }

  condition:
    any of them
}