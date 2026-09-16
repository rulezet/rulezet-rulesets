rule TTP_XOR_MULT_DOSStub_c4e2 {
  strings:
    $key_c4e2 = { 90 8a [2] e4 92 [2] a3 90 [2] e4 81 [2] aa 8d [2] a6 87 [2] b1 8c [2] aa c2 [2] 97 }

  condition:
    any of them
}