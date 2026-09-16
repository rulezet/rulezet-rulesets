rule TTP_XOR_MULT_DOSStub_c4ab {
  strings:
    $key_c4ab = { 90 c3 [2] e4 db [2] a3 d9 [2] e4 c8 [2] aa c4 [2] a6 ce [2] b1 c5 [2] aa 8b [2] 97 }

  condition:
    any of them
}