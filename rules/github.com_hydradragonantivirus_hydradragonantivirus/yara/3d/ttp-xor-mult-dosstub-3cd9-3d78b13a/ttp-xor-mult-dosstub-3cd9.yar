rule TTP_XOR_MULT_DOSStub_3cd9 {
  strings:
    $key_3cd9 = { 68 b1 [2] 1c a9 [2] 5b ab [2] 1c ba [2] 52 b6 [2] 5e bc [2] 49 b7 [2] 52 f9 [2] 6f }

  condition:
    any of them
}