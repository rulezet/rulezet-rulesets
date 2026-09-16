rule TTP_XOR_MULT_DOSStub_b7ab {
  strings:
    $key_b7ab = { e3 c3 [2] 97 db [2] d0 d9 [2] 97 c8 [2] d9 c4 [2] d5 ce [2] c2 c5 [2] d9 8b [2] e4 }

  condition:
    any of them
}