rule TTP_XOR_MULT_DOSStub_1000 {
  strings:
    $key_1000 = { 44 68 [2] 30 70 [2] 77 72 [2] 30 63 [2] 7e 6f [2] 72 65 [2] 65 6e [2] 7e 20 [2] 43 }

  condition:
    any of them
}