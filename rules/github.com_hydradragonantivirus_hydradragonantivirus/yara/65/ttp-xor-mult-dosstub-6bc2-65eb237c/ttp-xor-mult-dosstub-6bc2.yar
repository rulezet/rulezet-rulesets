rule TTP_XOR_MULT_DOSStub_6bc2 {
  strings:
    $key_6bc2 = { 3f aa [2] 4b b2 [2] 0c b0 [2] 4b a1 [2] 05 ad [2] 09 a7 [2] 1e ac [2] 05 e2 [2] 38 }

  condition:
    any of them
}