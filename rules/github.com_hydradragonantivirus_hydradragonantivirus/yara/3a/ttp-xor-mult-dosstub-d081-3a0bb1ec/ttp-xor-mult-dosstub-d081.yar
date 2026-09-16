rule TTP_XOR_MULT_DOSStub_d081 {
  strings:
    $key_d081 = { 84 e9 [2] f0 f1 [2] b7 f3 [2] f0 e2 [2] be ee [2] b2 e4 [2] a5 ef [2] be a1 [2] 83 }

  condition:
    any of them
}