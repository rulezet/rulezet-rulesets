rule TTP_XOR_MULT_DOSStub_e5ab {
  strings:
    $key_e5ab = { b1 c3 [2] c5 db [2] 82 d9 [2] c5 c8 [2] 8b c4 [2] 87 ce [2] 90 c5 [2] 8b 8b [2] b6 }

  condition:
    any of them
}