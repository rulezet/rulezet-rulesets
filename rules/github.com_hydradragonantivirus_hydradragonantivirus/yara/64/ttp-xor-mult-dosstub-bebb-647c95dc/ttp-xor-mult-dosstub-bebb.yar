rule TTP_XOR_MULT_DOSStub_bebb {
  strings:
    $key_bebb = { ea d3 [2] 9e cb [2] d9 c9 [2] 9e d8 [2] d0 d4 [2] dc de [2] cb d5 [2] d0 9b [2] ed }

  condition:
    any of them
}