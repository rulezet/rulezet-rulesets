rule TTP_XOR_MULT_DOSStub_4057 {
  strings:
    $key_4057 = { 14 3f [2] 60 27 [2] 27 25 [2] 60 34 [2] 2e 38 [2] 22 32 [2] 35 39 [2] 2e 77 [2] 13 }

  condition:
    any of them
}