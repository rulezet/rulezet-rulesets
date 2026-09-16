rule TTP_XOR_MULT_DOSStub_e1ab {
  strings:
    $key_e1ab = { b5 c3 [2] c1 db [2] 86 d9 [2] c1 c8 [2] 8f c4 [2] 83 ce [2] 94 c5 [2] 8f 8b [2] b2 }

  condition:
    any of them
}