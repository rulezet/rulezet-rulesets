rule TTP_XOR_MULT_DOSStub_c6e9 {
  strings:
    $key_c6e9 = { 92 81 [2] e6 99 [2] a1 9b [2] e6 8a [2] a8 86 [2] a4 8c [2] b3 87 [2] a8 c9 [2] 95 }

  condition:
    any of them
}