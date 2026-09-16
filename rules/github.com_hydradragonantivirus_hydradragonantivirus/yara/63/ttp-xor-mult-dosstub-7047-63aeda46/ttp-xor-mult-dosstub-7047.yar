rule TTP_XOR_MULT_DOSStub_7047 {
  strings:
    $key_7047 = { 24 2f [2] 50 37 [2] 17 35 [2] 50 24 [2] 1e 28 [2] 12 22 [2] 05 29 [2] 1e 67 [2] 23 }

  condition:
    any of them
}