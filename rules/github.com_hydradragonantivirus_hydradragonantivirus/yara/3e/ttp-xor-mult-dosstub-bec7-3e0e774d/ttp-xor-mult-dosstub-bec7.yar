rule TTP_XOR_MULT_DOSStub_bec7 {
  strings:
    $key_bec7 = { ea af [2] 9e b7 [2] d9 b5 [2] 9e a4 [2] d0 a8 [2] dc a2 [2] cb a9 [2] d0 e7 [2] ed }

  condition:
    any of them
}