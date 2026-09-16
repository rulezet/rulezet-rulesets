rule TTP_XOR_MULT_DOSStub_c287 {
  strings:
    $key_c287 = { 96 ef [2] e2 f7 [2] a5 f5 [2] e2 e4 [2] ac e8 [2] a0 e2 [2] b7 e9 [2] ac a7 [2] 91 }

  condition:
    any of them
}