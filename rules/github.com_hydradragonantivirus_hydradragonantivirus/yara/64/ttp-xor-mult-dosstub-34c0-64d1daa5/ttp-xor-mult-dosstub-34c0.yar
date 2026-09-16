rule TTP_XOR_MULT_DOSStub_34c0 {
  strings:
    $key_34c0 = { 60 a8 [2] 14 b0 [2] 53 b2 [2] 14 a3 [2] 5a af [2] 56 a5 [2] 41 ae [2] 5a e0 [2] 67 }

  condition:
    any of them
}