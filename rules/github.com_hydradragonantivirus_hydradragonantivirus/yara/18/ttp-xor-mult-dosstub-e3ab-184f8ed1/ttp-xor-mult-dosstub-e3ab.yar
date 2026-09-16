rule TTP_XOR_MULT_DOSStub_e3ab {
  strings:
    $key_e3ab = { b7 c3 [2] c3 db [2] 84 d9 [2] c3 c8 [2] 8d c4 [2] 81 ce [2] 96 c5 [2] 8d 8b [2] b0 }

  condition:
    any of them
}