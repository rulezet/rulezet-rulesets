rule TTP_XOR_MULT_DOSStub_0730 {
  strings:
    $key_0730 = { 53 58 [2] 27 40 [2] 60 42 [2] 27 53 [2] 69 5f [2] 65 55 [2] 72 5e [2] 69 10 [2] 54 }

  condition:
    any of them
}