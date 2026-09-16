rule TTP_XOR_MULT_DOSStub_3191 {
  strings:
    $key_3191 = { 65 f9 [2] 11 e1 [2] 56 e3 [2] 11 f2 [2] 5f fe [2] 53 f4 [2] 44 ff [2] 5f b1 [2] 62 }

  condition:
    any of them
}