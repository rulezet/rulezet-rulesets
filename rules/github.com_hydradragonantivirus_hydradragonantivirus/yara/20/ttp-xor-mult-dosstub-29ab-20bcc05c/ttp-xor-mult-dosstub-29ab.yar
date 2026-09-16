rule TTP_XOR_MULT_DOSStub_29ab {
  strings:
    $key_29ab = { 7d c3 [2] 09 db [2] 4e d9 [2] 09 c8 [2] 47 c4 [2] 4b ce [2] 5c c5 [2] 47 8b [2] 7a }

  condition:
    any of them
}