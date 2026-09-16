rule TTP_XOR_MULT_DOSStub_cdc7 {
  strings:
    $key_cdc7 = { 99 af [2] ed b7 [2] aa b5 [2] ed a4 [2] a3 a8 [2] af a2 [2] b8 a9 [2] a3 e7 [2] 9e }

  condition:
    any of them
}