rule TTP_XOR_MULT_DOSStub_cd89 {
  strings:
    $key_cd89 = { 99 e1 [2] ed f9 [2] aa fb [2] ed ea [2] a3 e6 [2] af ec [2] b8 e7 [2] a3 a9 [2] 9e }

  condition:
    any of them
}