rule TTP_XOR_MULT_DOSStub_a7ab {
  strings:
    $key_a7ab = { f3 c3 [2] 87 db [2] c0 d9 [2] 87 c8 [2] c9 c4 [2] c5 ce [2] d2 c5 [2] c9 8b [2] f4 }

  condition:
    any of them
}