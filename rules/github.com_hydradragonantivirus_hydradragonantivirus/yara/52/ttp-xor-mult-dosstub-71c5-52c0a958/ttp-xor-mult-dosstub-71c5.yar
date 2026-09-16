rule TTP_XOR_MULT_DOSStub_71c5 {
  strings:
    $key_71c5 = { 25 ad [2] 51 b5 [2] 16 b7 [2] 51 a6 [2] 1f aa [2] 13 a0 [2] 04 ab [2] 1f e5 [2] 22 }

  condition:
    any of them
}