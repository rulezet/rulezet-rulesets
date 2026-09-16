rule TTP_XOR_MULT_DOSStub_34ab {
  strings:
    $key_34ab = { 60 c3 [2] 14 db [2] 53 d9 [2] 14 c8 [2] 5a c4 [2] 56 ce [2] 41 c5 [2] 5a 8b [2] 67 }

  condition:
    any of them
}