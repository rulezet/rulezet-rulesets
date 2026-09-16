rule TTP_XOR_MULT_DOSStub_16ab {
  strings:
    $key_16ab = { 42 c3 [2] 36 db [2] 71 d9 [2] 36 c8 [2] 78 c4 [2] 74 ce [2] 63 c5 [2] 78 8b [2] 45 }

  condition:
    any of them
}