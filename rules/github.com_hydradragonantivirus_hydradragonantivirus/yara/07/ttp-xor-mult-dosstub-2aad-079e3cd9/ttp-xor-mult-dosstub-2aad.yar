rule TTP_XOR_MULT_DOSStub_2aad {
  strings:
    $key_2aad = { 7e c5 [2] 0a dd [2] 4d df [2] 0a ce [2] 44 c2 [2] 48 c8 [2] 5f c3 [2] 44 8d [2] 79 }

  condition:
    any of them
}