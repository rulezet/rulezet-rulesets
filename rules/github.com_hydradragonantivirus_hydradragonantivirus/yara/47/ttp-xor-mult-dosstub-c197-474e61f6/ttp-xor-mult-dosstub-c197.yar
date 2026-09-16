rule TTP_XOR_MULT_DOSStub_c197 {
  strings:
    $key_c197 = { 95 ff [2] e1 e7 [2] a6 e5 [2] e1 f4 [2] af f8 [2] a3 f2 [2] b4 f9 [2] af b7 [2] 92 }

  condition:
    any of them
}