rule TTP_XOR_MULT_DOSStub_c1e2 {
  strings:
    $key_c1e2 = { 95 8a [2] e1 92 [2] a6 90 [2] e1 81 [2] af 8d [2] a3 87 [2] b4 8c [2] af c2 [2] 92 }

  condition:
    any of them
}