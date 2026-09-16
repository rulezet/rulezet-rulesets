rule TTP_XOR_MULT_DOSStub_4ec5 {
  strings:
    $key_4ec5 = { 1a ad [2] 6e b5 [2] 29 b7 [2] 6e a6 [2] 20 aa [2] 2c a0 [2] 3b ab [2] 20 e5 [2] 1d }

  condition:
    any of them
}