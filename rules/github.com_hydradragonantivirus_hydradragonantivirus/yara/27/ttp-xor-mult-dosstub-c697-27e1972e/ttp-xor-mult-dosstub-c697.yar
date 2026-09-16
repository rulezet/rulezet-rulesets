rule TTP_XOR_MULT_DOSStub_c697 {
  strings:
    $key_c697 = { 92 ff [2] e6 e7 [2] a1 e5 [2] e6 f4 [2] a8 f8 [2] a4 f2 [2] b3 f9 [2] a8 b7 [2] 95 }

  condition:
    any of them
}