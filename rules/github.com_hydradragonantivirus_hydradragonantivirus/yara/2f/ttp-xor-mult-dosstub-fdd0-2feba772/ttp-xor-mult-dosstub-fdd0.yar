rule TTP_XOR_MULT_DOSStub_fdd0 {
  strings:
    $key_fdd0 = { a9 b8 [2] dd a0 [2] 9a a2 [2] dd b3 [2] 93 bf [2] 9f b5 [2] 88 be [2] 93 f0 [2] ae }

  condition:
    any of them
}