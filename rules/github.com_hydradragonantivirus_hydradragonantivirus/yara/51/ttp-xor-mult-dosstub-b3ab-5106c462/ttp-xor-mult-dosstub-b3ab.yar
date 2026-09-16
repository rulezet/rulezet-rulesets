rule TTP_XOR_MULT_DOSStub_b3ab {
  strings:
    $key_b3ab = { e7 c3 [2] 93 db [2] d4 d9 [2] 93 c8 [2] dd c4 [2] d1 ce [2] c6 c5 [2] dd 8b [2] e0 }

  condition:
    any of them
}