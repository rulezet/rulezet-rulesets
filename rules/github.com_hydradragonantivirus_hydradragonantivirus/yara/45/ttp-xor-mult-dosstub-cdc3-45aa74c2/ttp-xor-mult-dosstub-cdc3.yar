rule TTP_XOR_MULT_DOSStub_cdc3 {
  strings:
    $key_cdc3 = { 99 ab [2] ed b3 [2] aa b1 [2] ed a0 [2] a3 ac [2] af a6 [2] b8 ad [2] a3 e3 [2] 9e }

  condition:
    any of them
}