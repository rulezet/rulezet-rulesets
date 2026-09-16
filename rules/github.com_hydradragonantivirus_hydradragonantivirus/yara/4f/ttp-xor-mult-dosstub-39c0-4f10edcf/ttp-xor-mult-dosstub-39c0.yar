rule TTP_XOR_MULT_DOSStub_39c0 {
  strings:
    $key_39c0 = { 6d a8 [2] 19 b0 [2] 5e b2 [2] 19 a3 [2] 57 af [2] 5b a5 [2] 4c ae [2] 57 e0 [2] 6a }

  condition:
    any of them
}