rule TTP_XOR_MULT_DOSStub_26c0 {
  strings:
    $key_26c0 = { 72 a8 [2] 06 b0 [2] 41 b2 [2] 06 a3 [2] 48 af [2] 44 a5 [2] 53 ae [2] 48 e0 [2] 75 }

  condition:
    any of them
}