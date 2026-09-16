rule TTP_XOR_MULT_DOSStub_c28b {
  strings:
    $key_c28b = { 96 e3 [2] e2 fb [2] a5 f9 [2] e2 e8 [2] ac e4 [2] a0 ee [2] b7 e5 [2] ac ab [2] 91 }

  condition:
    any of them
}