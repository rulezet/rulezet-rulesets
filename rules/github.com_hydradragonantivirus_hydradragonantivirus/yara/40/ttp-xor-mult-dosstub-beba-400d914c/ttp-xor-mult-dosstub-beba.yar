rule TTP_XOR_MULT_DOSStub_beba {
  strings:
    $key_beba = { ea d2 [2] 9e ca [2] d9 c8 [2] 9e d9 [2] d0 d5 [2] dc df [2] cb d4 [2] d0 9a [2] ed }

  condition:
    any of them
}