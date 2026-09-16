rule TTP_XOR_MULT_DOSStub_fdab {
  strings:
    $key_fdab = { a9 c3 [2] dd db [2] 9a d9 [2] dd c8 [2] 93 c4 [2] 9f ce [2] 88 c5 [2] 93 8b [2] ae }

  condition:
    any of them
}