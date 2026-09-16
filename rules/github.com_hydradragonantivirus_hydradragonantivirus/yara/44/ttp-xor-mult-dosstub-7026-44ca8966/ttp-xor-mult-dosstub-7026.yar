rule TTP_XOR_MULT_DOSStub_7026 {
  strings:
    $key_7026 = { 24 4e [2] 50 56 [2] 17 54 [2] 50 45 [2] 1e 49 [2] 12 43 [2] 05 48 [2] 1e 06 [2] 23 }

  condition:
    any of them
}