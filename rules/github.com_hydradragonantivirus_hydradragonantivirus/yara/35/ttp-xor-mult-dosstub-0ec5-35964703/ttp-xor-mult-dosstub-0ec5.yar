rule TTP_XOR_MULT_DOSStub_0ec5 {
  strings:
    $key_0ec5 = { 5a ad [2] 2e b5 [2] 69 b7 [2] 2e a6 [2] 60 aa [2] 6c a0 [2] 7b ab [2] 60 e5 [2] 5d }

  condition:
    any of them
}