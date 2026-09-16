rule TTP_XOR_MULT_DOSStub_e8ab {
  strings:
    $key_e8ab = { bc c3 [2] c8 db [2] 8f d9 [2] c8 c8 [2] 86 c4 [2] 8a ce [2] 9d c5 [2] 86 8b [2] bb }

  condition:
    any of them
}