rule TTP_XOR_MULT_DOSStub_32ab {
  strings:
    $key_32ab = { 66 c3 [2] 12 db [2] 55 d9 [2] 12 c8 [2] 5c c4 [2] 50 ce [2] 47 c5 [2] 5c 8b [2] 61 }

  condition:
    any of them
}