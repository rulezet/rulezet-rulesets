rule TTP_XOR_MULT_DOSStub_beb7 {
  strings:
    $key_beb7 = { ea df [2] 9e c7 [2] d9 c5 [2] 9e d4 [2] d0 d8 [2] dc d2 [2] cb d9 [2] d0 97 [2] ed }

  condition:
    any of them
}