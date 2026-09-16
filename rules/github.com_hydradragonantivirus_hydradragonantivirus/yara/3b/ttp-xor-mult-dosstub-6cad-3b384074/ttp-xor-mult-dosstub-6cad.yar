rule TTP_XOR_MULT_DOSStub_6cad {
  strings:
    $key_6cad = { 38 c5 [2] 4c dd [2] 0b df [2] 4c ce [2] 02 c2 [2] 0e c8 [2] 19 c3 [2] 02 8d [2] 3f }

  condition:
    any of them
}