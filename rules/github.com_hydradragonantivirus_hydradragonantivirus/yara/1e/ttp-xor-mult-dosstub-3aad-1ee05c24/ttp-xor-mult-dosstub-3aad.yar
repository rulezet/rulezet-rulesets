rule TTP_XOR_MULT_DOSStub_3aad {
  strings:
    $key_3aad = { 6e c5 [2] 1a dd [2] 5d df [2] 1a ce [2] 54 c2 [2] 58 c8 [2] 4f c3 [2] 54 8d [2] 69 }

  condition:
    any of them
}