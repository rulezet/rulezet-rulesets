rule TTP_XOR_MULT_DOSStub_eac4 {
  strings:
    $key_eac4 = { be ac [2] ca b4 [2] 8d b6 [2] ca a7 [2] 84 ab [2] 88 a1 [2] 9f aa [2] 84 e4 [2] b9 }

  condition:
    any of them
}