rule TTP_XOR_MULT_DOSStub_d9ab {
  strings:
    $key_d9ab = { 8d c3 [2] f9 db [2] be d9 [2] f9 c8 [2] b7 c4 [2] bb ce [2] ac c5 [2] b7 8b [2] 8a }

  condition:
    any of them
}