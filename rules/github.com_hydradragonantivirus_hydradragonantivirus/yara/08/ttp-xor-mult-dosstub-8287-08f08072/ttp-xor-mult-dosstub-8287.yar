rule TTP_XOR_MULT_DOSStub_8287 {
  strings:
    $key_8287 = { d6 ef [2] a2 f7 [2] e5 f5 [2] a2 e4 [2] ec e8 [2] e0 e2 [2] f7 e9 [2] ec a7 [2] d1 }

  condition:
    any of them
}