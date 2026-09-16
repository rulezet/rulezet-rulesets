rule TTP_XOR_MULT_DOSStub_e896 {
  strings:
    $key_e896 = { bc fe [2] c8 e6 [2] 8f e4 [2] c8 f5 [2] 86 f9 [2] 8a f3 [2] 9d f8 [2] 86 b6 [2] bb }

  condition:
    any of them
}