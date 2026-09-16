rule TTP_XOR_MULT_DOSStub_24c3 {
  strings:
    $key_24c3 = { 70 ab [2] 04 b3 [2] 43 b1 [2] 04 a0 [2] 4a ac [2] 46 a6 [2] 51 ad [2] 4a e3 [2] 77 }

  condition:
    any of them
}