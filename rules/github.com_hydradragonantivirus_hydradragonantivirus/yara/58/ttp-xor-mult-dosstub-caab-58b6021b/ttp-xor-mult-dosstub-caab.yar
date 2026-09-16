rule TTP_XOR_MULT_DOSStub_caab {
  strings:
    $key_caab = { 9e c3 [2] ea db [2] ad d9 [2] ea c8 [2] a4 c4 [2] a8 ce [2] bf c5 [2] a4 8b [2] 99 }

  condition:
    any of them
}