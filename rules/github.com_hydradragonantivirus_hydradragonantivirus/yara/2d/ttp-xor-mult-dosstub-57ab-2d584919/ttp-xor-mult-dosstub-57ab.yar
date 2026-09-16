rule TTP_XOR_MULT_DOSStub_57ab {
  strings:
    $key_57ab = { 03 c3 [2] 77 db [2] 30 d9 [2] 77 c8 [2] 39 c4 [2] 35 ce [2] 22 c5 [2] 39 8b [2] 04 }

  condition:
    any of them
}