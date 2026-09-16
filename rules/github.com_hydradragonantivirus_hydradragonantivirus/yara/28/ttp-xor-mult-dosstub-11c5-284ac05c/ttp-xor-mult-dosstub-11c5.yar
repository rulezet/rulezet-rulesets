rule TTP_XOR_MULT_DOSStub_11c5 {
  strings:
    $key_11c5 = { 45 ad [2] 31 b5 [2] 76 b7 [2] 31 a6 [2] 7f aa [2] 73 a0 [2] 64 ab [2] 7f e5 [2] 42 }

  condition:
    any of them
}