rule TTP_XOR_MULT_DOSStub_05ab {
  strings:
    $key_05ab = { 51 c3 [2] 25 db [2] 62 d9 [2] 25 c8 [2] 6b c4 [2] 67 ce [2] 70 c5 [2] 6b 8b [2] 56 }

  condition:
    any of them
}