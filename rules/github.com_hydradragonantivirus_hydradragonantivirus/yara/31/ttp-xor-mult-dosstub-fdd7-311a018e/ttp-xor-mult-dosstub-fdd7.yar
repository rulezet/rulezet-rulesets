rule TTP_XOR_MULT_DOSStub_fdd7 {
  strings:
    $key_fdd7 = { a9 bf [2] dd a7 [2] 9a a5 [2] dd b4 [2] 93 b8 [2] 9f b2 [2] 88 b9 [2] 93 f7 [2] ae }

  condition:
    any of them
}