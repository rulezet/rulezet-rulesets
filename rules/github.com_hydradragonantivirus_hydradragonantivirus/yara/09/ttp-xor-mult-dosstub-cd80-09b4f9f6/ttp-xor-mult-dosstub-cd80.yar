rule TTP_XOR_MULT_DOSStub_cd80 {
  strings:
    $key_cd80 = { 99 e8 [2] ed f0 [2] aa f2 [2] ed e3 [2] a3 ef [2] af e5 [2] b8 ee [2] a3 a0 [2] 9e }

  condition:
    any of them
}