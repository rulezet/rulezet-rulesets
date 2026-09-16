rule TTP_XOR_MULT_DOSStub_34c5 {
  strings:
    $key_34c5 = { 60 ad [2] 14 b5 [2] 53 b7 [2] 14 a6 [2] 5a aa [2] 56 a0 [2] 41 ab [2] 5a e5 [2] 67 }

  condition:
    any of them
}