rule TTP_XOR_MULT_DOSStub_b4ab {
  strings:
    $key_b4ab = { e0 c3 [2] 94 db [2] d3 d9 [2] 94 c8 [2] da c4 [2] d6 ce [2] c1 c5 [2] da 8b [2] e7 }

  condition:
    any of them
}