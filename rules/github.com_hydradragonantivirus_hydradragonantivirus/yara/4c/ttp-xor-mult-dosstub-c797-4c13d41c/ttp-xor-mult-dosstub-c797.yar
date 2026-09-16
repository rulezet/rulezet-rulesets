rule TTP_XOR_MULT_DOSStub_c797 {
  strings:
    $key_c797 = { 93 ff [2] e7 e7 [2] a0 e5 [2] e7 f4 [2] a9 f8 [2] a5 f2 [2] b2 f9 [2] a9 b7 [2] 94 }

  condition:
    any of them
}