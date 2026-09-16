rule TTP_XOR_MULT_DOSStub_cd86 {
  strings:
    $key_cd86 = { 99 ee [2] ed f6 [2] aa f4 [2] ed e5 [2] a3 e9 [2] af e3 [2] b8 e8 [2] a3 a6 [2] 9e }

  condition:
    any of them
}