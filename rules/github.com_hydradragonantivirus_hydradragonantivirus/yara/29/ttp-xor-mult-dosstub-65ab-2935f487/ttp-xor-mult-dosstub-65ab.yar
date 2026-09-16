rule TTP_XOR_MULT_DOSStub_65ab {
  strings:
    $key_65ab = { 31 c3 [2] 45 db [2] 02 d9 [2] 45 c8 [2] 0b c4 [2] 07 ce [2] 10 c5 [2] 0b 8b [2] 36 }

  condition:
    any of them
}