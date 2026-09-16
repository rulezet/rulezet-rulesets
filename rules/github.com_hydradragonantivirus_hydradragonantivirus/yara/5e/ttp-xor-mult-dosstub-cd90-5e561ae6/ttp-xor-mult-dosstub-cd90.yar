rule TTP_XOR_MULT_DOSStub_cd90 {
  strings:
    $key_cd90 = { 99 f8 [2] ed e0 [2] aa e2 [2] ed f3 [2] a3 ff [2] af f5 [2] b8 fe [2] a3 b0 [2] 9e }

  condition:
    any of them
}