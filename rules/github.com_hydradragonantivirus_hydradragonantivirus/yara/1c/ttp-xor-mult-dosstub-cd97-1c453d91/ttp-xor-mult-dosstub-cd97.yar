rule TTP_XOR_MULT_DOSStub_cd97 {
  strings:
    $key_cd97 = { 99 ff [2] ed e7 [2] aa e5 [2] ed f4 [2] a3 f8 [2] af f2 [2] b8 f9 [2] a3 b7 [2] 9e }

  condition:
    any of them
}