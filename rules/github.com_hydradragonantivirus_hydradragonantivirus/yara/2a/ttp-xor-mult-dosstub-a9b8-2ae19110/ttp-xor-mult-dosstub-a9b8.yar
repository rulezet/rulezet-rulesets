rule TTP_XOR_MULT_DOSStub_a9b8 {
  strings:
    $key_a9b8 = { fd d0 [2] 89 c8 [2] ce ca [2] 89 db [2] c7 d7 [2] cb dd [2] dc d6 [2] c7 98 [2] fa }

  condition:
    any of them
}