rule TTP_XOR_MULT_DOSStub_61c0 {
  strings:
    $key_61c0 = { 35 a8 [2] 41 b0 [2] 06 b2 [2] 41 a3 [2] 0f af [2] 03 a5 [2] 14 ae [2] 0f e0 [2] 32 }

  condition:
    any of them
}