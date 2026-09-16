rule TTP_XOR_MULT_DOSStub_e1d1 {
  strings:
    $key_e1d1 = { b5 b9 [2] c1 a1 [2] 86 a3 [2] c1 b2 [2] 8f be [2] 83 b4 [2] 94 bf [2] 8f f1 [2] b2 }

  condition:
    any of them
}