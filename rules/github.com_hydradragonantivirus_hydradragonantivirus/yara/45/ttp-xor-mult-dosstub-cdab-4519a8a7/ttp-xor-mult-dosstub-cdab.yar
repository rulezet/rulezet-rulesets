rule TTP_XOR_MULT_DOSStub_cdab {
  strings:
    $key_cdab = { 99 c3 [2] ed db [2] aa d9 [2] ed c8 [2] a3 c4 [2] af ce [2] b8 c5 [2] a3 8b [2] 9e }

  condition:
    any of them
}