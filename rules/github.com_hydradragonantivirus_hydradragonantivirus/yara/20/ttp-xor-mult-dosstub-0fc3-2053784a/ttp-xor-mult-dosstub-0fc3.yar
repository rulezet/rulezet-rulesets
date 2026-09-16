rule TTP_XOR_MULT_DOSStub_0fc3 {
  strings:
    $key_0fc3 = { 5b ab [2] 2f b3 [2] 68 b1 [2] 2f a0 [2] 61 ac [2] 6d a6 [2] 7a ad [2] 61 e3 [2] 5c }

  condition:
    any of them
}