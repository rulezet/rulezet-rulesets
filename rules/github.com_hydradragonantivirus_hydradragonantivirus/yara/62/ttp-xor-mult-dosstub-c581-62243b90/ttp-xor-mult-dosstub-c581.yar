rule TTP_XOR_MULT_DOSStub_c581 {
  strings:
    $key_c581 = { 91 e9 [2] e5 f1 [2] a2 f3 [2] e5 e2 [2] ab ee [2] a7 e4 [2] b0 ef [2] ab a1 [2] 96 }

  condition:
    any of them
}