rule TTP_XOR_MULT_DOSStub_26ab {
  strings:
    $key_26ab = { 72 c3 [2] 06 db [2] 41 d9 [2] 06 c8 [2] 48 c4 [2] 44 ce [2] 53 c5 [2] 48 8b [2] 75 }

  condition:
    any of them
}