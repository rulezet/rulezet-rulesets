rule TTP_XOR_MULT_DOSStub_7020 {
  strings:
    $key_7020 = { 24 48 [2] 50 50 [2] 17 52 [2] 50 43 [2] 1e 4f [2] 12 45 [2] 05 4e [2] 1e 00 [2] 23 }

  condition:
    any of them
}