rule TTP_XOR_MULT_DOSStub_5891 {
  strings:
    $key_5891 = { 0c f9 [2] 78 e1 [2] 3f e3 [2] 78 f2 [2] 36 fe [2] 3a f4 [2] 2d ff [2] 36 b1 [2] 0b }

  condition:
    any of them
}