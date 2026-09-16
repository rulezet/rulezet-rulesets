rule TTP_XOR_MULT_DOSStub_0541 {
  strings:
    $key_0541 = { 51 29 [2] 25 31 [2] 62 33 [2] 25 22 [2] 6b 2e [2] 67 24 [2] 70 2f [2] 6b 61 [2] 56 }

  condition:
    any of them
}