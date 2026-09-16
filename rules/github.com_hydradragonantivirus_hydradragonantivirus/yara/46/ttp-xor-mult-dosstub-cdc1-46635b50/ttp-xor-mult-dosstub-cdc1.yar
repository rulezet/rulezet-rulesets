rule TTP_XOR_MULT_DOSStub_cdc1 {
  strings:
    $key_cdc1 = { 99 a9 [2] ed b1 [2] aa b3 [2] ed a2 [2] a3 ae [2] af a4 [2] b8 af [2] a3 e1 [2] 9e }

  condition:
    any of them
}