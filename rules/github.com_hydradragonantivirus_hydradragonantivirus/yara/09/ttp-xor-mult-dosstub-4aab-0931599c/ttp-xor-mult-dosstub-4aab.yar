rule TTP_XOR_MULT_DOSStub_4aab {
  strings:
    $key_4aab = { 1e c3 [2] 6a db [2] 2d d9 [2] 6a c8 [2] 24 c4 [2] 28 ce [2] 3f c5 [2] 24 8b [2] 19 }

  condition:
    any of them
}