rule TTP_XOR_MULT_DOSStub_7037 {
  strings:
    $key_7037 = { 24 5f [2] 50 47 [2] 17 45 [2] 50 54 [2] 1e 58 [2] 12 52 [2] 05 59 [2] 1e 17 [2] 23 }

  condition:
    any of them
}