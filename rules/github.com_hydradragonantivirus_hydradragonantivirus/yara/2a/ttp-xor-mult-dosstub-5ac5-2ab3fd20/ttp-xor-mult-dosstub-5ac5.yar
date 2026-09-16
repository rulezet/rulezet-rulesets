rule TTP_XOR_MULT_DOSStub_5ac5 {
  strings:
    $key_5ac5 = { 0e ad [2] 7a b5 [2] 3d b7 [2] 7a a6 [2] 34 aa [2] 38 a0 [2] 2f ab [2] 34 e5 [2] 09 }

  condition:
    any of them
}