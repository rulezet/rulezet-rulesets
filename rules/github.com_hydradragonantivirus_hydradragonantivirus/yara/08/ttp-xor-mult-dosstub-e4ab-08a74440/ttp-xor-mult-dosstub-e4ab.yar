rule TTP_XOR_MULT_DOSStub_e4ab {
  strings:
    $key_e4ab = { b0 c3 [2] c4 db [2] 83 d9 [2] c4 c8 [2] 8a c4 [2] 86 ce [2] 91 c5 [2] 8a 8b [2] b7 }

  condition:
    any of them
}