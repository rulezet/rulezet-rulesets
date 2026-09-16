rule TTP_XOR_MULT_DOSStub_bec3 {
  strings:
    $key_bec3 = { ea ab [2] 9e b3 [2] d9 b1 [2] 9e a0 [2] d0 ac [2] dc a6 [2] cb ad [2] d0 e3 [2] ed }

  condition:
    any of them
}