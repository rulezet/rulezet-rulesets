rule TTP_XOR_MULT_DOSStub_12ab {
  strings:
    $key_12ab = { 46 c3 [2] 32 db [2] 75 d9 [2] 32 c8 [2] 7c c4 [2] 70 ce [2] 67 c5 [2] 7c 8b [2] 41 }

  condition:
    any of them
}