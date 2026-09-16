rule TTP_XOR_MULT_DOSStub_2cd9 {
  strings:
    $key_2cd9 = { 78 b1 [2] 0c a9 [2] 4b ab [2] 0c ba [2] 42 b6 [2] 4e bc [2] 59 b7 [2] 42 f9 [2] 7f }

  condition:
    any of them
}