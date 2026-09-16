rule TTP_XOR_MULT_DOSStub_cdc2 {
  strings:
    $key_cdc2 = { 99 aa [2] ed b2 [2] aa b0 [2] ed a1 [2] a3 ad [2] af a7 [2] b8 ac [2] a3 e2 [2] 9e }

  condition:
    any of them
}