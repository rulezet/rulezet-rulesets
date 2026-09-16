rule TTP_XOR_MULT_DOSStub_c481 {
  strings:
    $key_c481 = { 90 e9 [2] e4 f1 [2] a3 f3 [2] e4 e2 [2] aa ee [2] a6 e4 [2] b1 ef [2] aa a1 [2] 97 }

  condition:
    any of them
}