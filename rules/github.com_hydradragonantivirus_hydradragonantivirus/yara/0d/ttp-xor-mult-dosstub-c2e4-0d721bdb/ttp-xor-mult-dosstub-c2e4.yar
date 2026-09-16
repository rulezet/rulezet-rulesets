rule TTP_XOR_MULT_DOSStub_c2e4 {
  strings:
    $key_c2e4 = { 96 8c [2] e2 94 [2] a5 96 [2] e2 87 [2] ac 8b [2] a0 81 [2] b7 8a [2] ac c4 [2] 91 }

  condition:
    any of them
}