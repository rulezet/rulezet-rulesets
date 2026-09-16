rule TTP_XOR_MULT_DOSStub_fdad {
  strings:
    $key_fdad = { a9 c5 [2] dd dd [2] 9a df [2] dd ce [2] 93 c2 [2] 9f c8 [2] 88 c3 [2] 93 8d [2] ae }

  condition:
    any of them
}