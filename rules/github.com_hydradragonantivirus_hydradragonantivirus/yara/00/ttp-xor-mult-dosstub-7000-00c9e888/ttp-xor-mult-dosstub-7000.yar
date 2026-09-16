rule TTP_XOR_MULT_DOSStub_7000 {
  strings:
    $key_7000 = { 24 68 [2] 50 70 [2] 17 72 [2] 50 63 [2] 1e 6f [2] 12 65 [2] 05 6e [2] 1e 20 [2] 23 }

  condition:
    any of them
}