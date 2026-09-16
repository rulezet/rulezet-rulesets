rule TTP_XOR_MULT_DOSStub_c2e2 {
  strings:
    $key_c2e2 = { 96 8a [2] e2 92 [2] a5 90 [2] e2 81 [2] ac 8d [2] a0 87 [2] b7 8c [2] ac c2 [2] 91 }

  condition:
    any of them
}