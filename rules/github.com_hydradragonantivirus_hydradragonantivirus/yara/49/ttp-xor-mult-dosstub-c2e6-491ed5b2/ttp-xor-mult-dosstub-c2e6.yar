rule TTP_XOR_MULT_DOSStub_c2e6 {
  strings:
    $key_c2e6 = { 96 8e [2] e2 96 [2] a5 94 [2] e2 85 [2] ac 89 [2] a0 83 [2] b7 88 [2] ac c6 [2] 91 }

  condition:
    any of them
}