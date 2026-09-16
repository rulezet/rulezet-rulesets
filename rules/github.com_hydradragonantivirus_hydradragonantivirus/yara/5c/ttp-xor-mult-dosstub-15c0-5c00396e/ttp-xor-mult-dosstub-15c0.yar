rule TTP_XOR_MULT_DOSStub_15c0 {
  strings:
    $key_15c0 = { 41 a8 [2] 35 b0 [2] 72 b2 [2] 35 a3 [2] 7b af [2] 77 a5 [2] 60 ae [2] 7b e0 [2] 46 }

  condition:
    any of them
}