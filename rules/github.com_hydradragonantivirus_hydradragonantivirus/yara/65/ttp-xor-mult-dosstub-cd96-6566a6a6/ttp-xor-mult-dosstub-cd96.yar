rule TTP_XOR_MULT_DOSStub_cd96 {
  strings:
    $key_cd96 = { 99 fe [2] ed e6 [2] aa e4 [2] ed f5 [2] a3 f9 [2] af f3 [2] b8 f8 [2] a3 b6 [2] 9e }

  condition:
    any of them
}