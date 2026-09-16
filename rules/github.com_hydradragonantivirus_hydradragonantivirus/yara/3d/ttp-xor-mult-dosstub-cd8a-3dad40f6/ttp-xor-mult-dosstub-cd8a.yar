rule TTP_XOR_MULT_DOSStub_cd8a {
  strings:
    $key_cd8a = { 99 e2 [2] ed fa [2] aa f8 [2] ed e9 [2] a3 e5 [2] af ef [2] b8 e4 [2] a3 aa [2] 9e }

  condition:
    any of them
}