rule TTP_XOR_MULT_DOSStub_e0ab {
  strings:
    $key_e0ab = { b4 c3 [2] c0 db [2] 87 d9 [2] c0 c8 [2] 8e c4 [2] 82 ce [2] 95 c5 [2] 8e 8b [2] b3 }

  condition:
    any of them
}