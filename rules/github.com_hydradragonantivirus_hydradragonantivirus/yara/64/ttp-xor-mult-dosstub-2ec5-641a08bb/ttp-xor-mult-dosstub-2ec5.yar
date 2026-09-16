rule TTP_XOR_MULT_DOSStub_2ec5 {
  strings:
    $key_2ec5 = { 7a ad [2] 0e b5 [2] 49 b7 [2] 0e a6 [2] 40 aa [2] 4c a0 [2] 5b ab [2] 40 e5 [2] 7d }

  condition:
    any of them
}