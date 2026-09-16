rule TTP_XOR_MULT_DOSStub_beb5 {
  strings:
    $key_beb5 = { ea dd [2] 9e c5 [2] d9 c7 [2] 9e d6 [2] d0 da [2] dc d0 [2] cb db [2] d0 95 [2] ed }

  condition:
    any of them
}