rule TTP_XOR_MULT_DOSStub_01ab {
  strings:
    $key_01ab = { 55 c3 [2] 21 db [2] 66 d9 [2] 21 c8 [2] 6f c4 [2] 63 ce [2] 74 c5 [2] 6f 8b [2] 52 }

  condition:
    any of them
}