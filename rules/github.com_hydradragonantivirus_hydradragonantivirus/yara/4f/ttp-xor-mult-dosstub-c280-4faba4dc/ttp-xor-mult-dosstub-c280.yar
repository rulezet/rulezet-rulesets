rule TTP_XOR_MULT_DOSStub_c280 {
  strings:
    $key_c280 = { 96 e8 [2] e2 f0 [2] a5 f2 [2] e2 e3 [2] ac ef [2] a0 e5 [2] b7 ee [2] ac a0 [2] 91 }

  condition:
    any of them
}