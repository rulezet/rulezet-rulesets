rule TTP_XOR_MULT_DOSStub_7cd9 {
  strings:
    $key_7cd9 = { 28 b1 [2] 5c a9 [2] 1b ab [2] 5c ba [2] 12 b6 [2] 1e bc [2] 09 b7 [2] 12 f9 [2] 2f }

  condition:
    any of them
}