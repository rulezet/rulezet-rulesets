rule TTP_XOR_MULT_DOSStub_cdc0 {
  strings:
    $key_cdc0 = { 99 a8 [2] ed b0 [2] aa b2 [2] ed a3 [2] a3 af [2] af a5 [2] b8 ae [2] a3 e0 [2] 9e }

  condition:
    any of them
}