rule TTP_XOR_MULT_DOSStub_1030 {
  strings:
    $key_1030 = { 44 58 [2] 30 40 [2] 77 42 [2] 30 53 [2] 7e 5f [2] 72 55 [2] 65 5e [2] 7e 10 [2] 43 }

  condition:
    any of them
}