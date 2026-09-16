rule TTP_XOR_MULT_DOSStub_7031 {
  strings:
    $key_7031 = { 24 59 [2] 50 41 [2] 17 43 [2] 50 52 [2] 1e 5e [2] 12 54 [2] 05 5f [2] 1e 11 [2] 23 }

  condition:
    any of them
}