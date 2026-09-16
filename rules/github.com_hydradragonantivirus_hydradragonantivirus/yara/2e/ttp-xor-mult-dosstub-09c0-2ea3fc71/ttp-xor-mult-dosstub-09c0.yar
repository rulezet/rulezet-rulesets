rule TTP_XOR_MULT_DOSStub_09c0 {
  strings:
    $key_09c0 = { 5d a8 [2] 29 b0 [2] 6e b2 [2] 29 a3 [2] 67 af [2] 6b a5 [2] 7c ae [2] 67 e0 [2] 5a }

  condition:
    any of them
}