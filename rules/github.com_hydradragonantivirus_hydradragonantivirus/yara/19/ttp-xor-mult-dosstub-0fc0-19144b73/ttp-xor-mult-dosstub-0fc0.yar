rule TTP_XOR_MULT_DOSStub_0fc0 {
  strings:
    $key_0fc0 = { 5b a8 [2] 2f b0 [2] 68 b2 [2] 2f a3 [2] 61 af [2] 6d a5 [2] 7a ae [2] 61 e0 [2] 5c }

  condition:
    any of them
}