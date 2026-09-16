rule TTP_XOR_MULT_DOSStub_c6e2 {
  strings:
    $key_c6e2 = { 92 8a [2] e6 92 [2] a1 90 [2] e6 81 [2] a8 8d [2] a4 87 [2] b3 8c [2] a8 c2 [2] 95 }

  condition:
    any of them
}