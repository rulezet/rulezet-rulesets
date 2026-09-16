rule TTP_XOR_MULT_DOSStub_cd81 {
  strings:
    $key_cd81 = { 99 e9 [2] ed f1 [2] aa f3 [2] ed e2 [2] a3 ee [2] af e4 [2] b8 ef [2] a3 a1 [2] 9e }

  condition:
    any of them
}