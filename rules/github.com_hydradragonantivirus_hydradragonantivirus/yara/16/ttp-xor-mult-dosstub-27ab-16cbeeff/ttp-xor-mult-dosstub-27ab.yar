rule TTP_XOR_MULT_DOSStub_27ab {
  strings:
    $key_27ab = { 73 c3 [2] 07 db [2] 40 d9 [2] 07 c8 [2] 49 c4 [2] 45 ce [2] 52 c5 [2] 49 8b [2] 74 }

  condition:
    any of them
}