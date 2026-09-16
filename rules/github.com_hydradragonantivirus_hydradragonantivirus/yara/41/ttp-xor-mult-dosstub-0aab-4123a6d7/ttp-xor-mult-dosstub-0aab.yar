rule TTP_XOR_MULT_DOSStub_0aab {
  strings:
    $key_0aab = { 5e c3 [2] 2a db [2] 6d d9 [2] 2a c8 [2] 64 c4 [2] 68 ce [2] 7f c5 [2] 64 8b [2] 59 }

  condition:
    any of them
}