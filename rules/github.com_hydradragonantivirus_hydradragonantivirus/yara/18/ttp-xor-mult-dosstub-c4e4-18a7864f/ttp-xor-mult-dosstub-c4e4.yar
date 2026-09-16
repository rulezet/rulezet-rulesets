rule TTP_XOR_MULT_DOSStub_c4e4 {
  strings:
    $key_c4e4 = { 90 8c [2] e4 94 [2] a3 96 [2] e4 87 [2] aa 8b [2] a6 81 [2] b1 8a [2] aa c4 [2] 97 }

  condition:
    any of them
}