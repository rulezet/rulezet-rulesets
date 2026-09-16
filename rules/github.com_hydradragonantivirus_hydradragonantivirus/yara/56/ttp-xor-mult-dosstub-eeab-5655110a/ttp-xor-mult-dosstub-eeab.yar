rule TTP_XOR_MULT_DOSStub_eeab {
  strings:
    $key_eeab = { ba c3 [2] ce db [2] 89 d9 [2] ce c8 [2] 80 c4 [2] 8c ce [2] 9b c5 [2] 80 8b [2] bd }

  condition:
    any of them
}