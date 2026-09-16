rule TTP_XOR_MULT_DOSStub_2496 {
  strings:
    $key_2496 = { 70 fe [2] 04 e6 [2] 43 e4 [2] 04 f5 [2] 4a f9 [2] 46 f3 [2] 51 f8 [2] 4a b6 [2] 77 }

  condition:
    any of them
}