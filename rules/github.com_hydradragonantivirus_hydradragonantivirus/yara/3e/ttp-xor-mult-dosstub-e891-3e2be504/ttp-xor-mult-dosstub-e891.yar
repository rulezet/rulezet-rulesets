rule TTP_XOR_MULT_DOSStub_e891 {
  strings:
    $key_e891 = { bc f9 [2] c8 e1 [2] 8f e3 [2] c8 f2 [2] 86 fe [2] 8a f4 [2] 9d ff [2] 86 b1 [2] bb }

  condition:
    any of them
}