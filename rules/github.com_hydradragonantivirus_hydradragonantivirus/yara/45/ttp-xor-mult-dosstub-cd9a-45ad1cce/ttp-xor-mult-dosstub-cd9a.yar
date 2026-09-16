rule TTP_XOR_MULT_DOSStub_cd9a {
  strings:
    $key_cd9a = { 99 f2 [2] ed ea [2] aa e8 [2] ed f9 [2] a3 f5 [2] af ff [2] b8 f4 [2] a3 ba [2] 9e }

  condition:
    any of them
}