rule TTP_XOR_MULT_DOSStub_bcb3 {
  strings:
    $key_bcb3 = { e8 db [2] 9c c3 [2] db c1 [2] 9c d0 [2] d2 dc [2] de d6 [2] c9 dd [2] d2 93 [2] ef }

  condition:
    any of them
}