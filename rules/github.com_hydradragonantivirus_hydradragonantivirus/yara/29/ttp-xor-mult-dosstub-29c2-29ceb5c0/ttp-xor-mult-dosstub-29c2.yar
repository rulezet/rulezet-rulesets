rule TTP_XOR_MULT_DOSStub_29c2 {
  strings:
    $key_29c2 = { 7d aa [2] 09 b2 [2] 4e b0 [2] 09 a1 [2] 47 ad [2] 4b a7 [2] 5c ac [2] 47 e2 [2] 7a }

  condition:
    any of them
}