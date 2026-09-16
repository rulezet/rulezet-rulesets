rule TTP_XOR_MULT_DOSStub_05c5 {
  strings:
    $key_05c5 = { 51 ad [2] 25 b5 [2] 62 b7 [2] 25 a6 [2] 6b aa [2] 67 a0 [2] 70 ab [2] 6b e5 [2] 56 }

  condition:
    any of them
}