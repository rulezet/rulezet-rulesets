rule TTP_XOR_MULT_DOSStub_0cad {
  strings:
    $key_0cad = { 58 c5 [2] 2c dd [2] 6b df [2] 2c ce [2] 62 c2 [2] 6e c8 [2] 79 c3 [2] 62 8d [2] 5f }

  condition:
    any of them
}