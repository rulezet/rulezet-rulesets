rule TTP_XOR_MULT_DOSStub_dd87 {
  strings:
    $key_dd87 = { 89 ef [2] fd f7 [2] ba f5 [2] fd e4 [2] b3 e8 [2] bf e2 [2] a8 e9 [2] b3 a7 [2] 8e }

  condition:
    any of them
}