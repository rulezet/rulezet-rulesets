rule TTP_XOR_MULT_DOSStub_cdc5 {
  strings:
    $key_cdc5 = { 99 ad [2] ed b5 [2] aa b7 [2] ed a6 [2] a3 aa [2] af a0 [2] b8 ab [2] a3 e5 [2] 9e }

  condition:
    any of them
}