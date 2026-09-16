rule TTP_XOR_MULT_DOSStub_dd80 {
  strings:
    $key_dd80 = { 89 e8 [2] fd f0 [2] ba f2 [2] fd e3 [2] b3 ef [2] bf e5 [2] a8 ee [2] b3 a0 [2] 8e }

  condition:
    any of them
}