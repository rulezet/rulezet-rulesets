rule TTP_XOR_MULT_DOSStub_33ab {
  strings:
    $key_33ab = { 67 c3 [2] 13 db [2] 54 d9 [2] 13 c8 [2] 5d c4 [2] 51 ce [2] 46 c5 [2] 5d 8b [2] 60 }

  condition:
    any of them
}