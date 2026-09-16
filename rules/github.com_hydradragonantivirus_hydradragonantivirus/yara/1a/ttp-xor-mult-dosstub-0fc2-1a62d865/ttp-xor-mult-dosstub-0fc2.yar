rule TTP_XOR_MULT_DOSStub_0fc2 {
  strings:
    $key_0fc2 = { 5b aa [2] 2f b2 [2] 68 b0 [2] 2f a1 [2] 61 ad [2] 6d a7 [2] 7a ac [2] 61 e2 [2] 5c }

  condition:
    any of them
}