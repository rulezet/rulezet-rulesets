rule TTP_XOR_MULT_DOSStub_29c0 {
  strings:
    $key_29c0 = { 7d a8 [2] 09 b0 [2] 4e b2 [2] 09 a3 [2] 47 af [2] 4b a5 [2] 5c ae [2] 47 e0 [2] 7a }

  condition:
    any of them
}