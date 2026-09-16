rule TTP_XOR_MULT_DOSStub_53ab {
  strings:
    $key_53ab = { 07 c3 [2] 73 db [2] 34 d9 [2] 73 c8 [2] 3d c4 [2] 31 ce [2] 26 c5 [2] 3d 8b [2] 00 }

  condition:
    any of them
}