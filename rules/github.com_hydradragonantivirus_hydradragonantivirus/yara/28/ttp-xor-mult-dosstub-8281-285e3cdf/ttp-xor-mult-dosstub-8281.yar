rule TTP_XOR_MULT_DOSStub_8281 {
  strings:
    $key_8281 = { d6 e9 [2] a2 f1 [2] e5 f3 [2] a2 e2 [2] ec ee [2] e0 e4 [2] f7 ef [2] ec a1 [2] d1 }

  condition:
    any of them
}