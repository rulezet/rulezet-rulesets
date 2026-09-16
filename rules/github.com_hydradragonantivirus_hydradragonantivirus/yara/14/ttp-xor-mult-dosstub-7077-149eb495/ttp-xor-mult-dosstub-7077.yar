rule TTP_XOR_MULT_DOSStub_7077 {
  strings:
    $key_7077 = { 24 1f [2] 50 07 [2] 17 05 [2] 50 14 [2] 1e 18 [2] 12 12 [2] 05 19 [2] 1e 57 [2] 23 }

  condition:
    any of them
}