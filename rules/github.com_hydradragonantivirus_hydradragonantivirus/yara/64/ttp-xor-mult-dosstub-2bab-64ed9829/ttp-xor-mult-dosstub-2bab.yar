rule TTP_XOR_MULT_DOSStub_2bab {
  strings:
    $key_2bab = { 7f c3 [2] 0b db [2] 4c d9 [2] 0b c8 [2] 45 c4 [2] 49 ce [2] 5e c5 [2] 45 8b [2] 78 }

  condition:
    any of them
}