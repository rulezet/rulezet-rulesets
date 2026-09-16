rule TTP_XOR_MULT_DOSStub_1cad {
  strings:
    $key_1cad = { 48 c5 [2] 3c dd [2] 7b df [2] 3c ce [2] 72 c2 [2] 7e c8 [2] 69 c3 [2] 72 8d [2] 4f }

  condition:
    any of them
}