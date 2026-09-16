rule TTP_XOR_MULT_DOSStub_7ac5 {
  strings:
    $key_7ac5 = { 2e ad [2] 5a b5 [2] 1d b7 [2] 5a a6 [2] 14 aa [2] 18 a0 [2] 0f ab [2] 14 e5 [2] 29 }

  condition:
    any of them
}