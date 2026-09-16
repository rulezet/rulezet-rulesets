rule TTP_XOR_MULT_DOSStub_72c0 {
  strings:
    $key_72c0 = { 26 a8 [2] 52 b0 [2] 15 b2 [2] 52 a3 [2] 1c af [2] 10 a5 [2] 07 ae [2] 1c e0 [2] 21 }

  condition:
    any of them
}