rule TTP_XOR_MULT_DOSStub_e491 {
  strings:
    $key_e491 = { b0 f9 [2] c4 e1 [2] 83 e3 [2] c4 f2 [2] 8a fe [2] 86 f4 [2] 91 ff [2] 8a b1 [2] b7 }

  condition:
    any of them
}