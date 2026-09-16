rule TTP_XOR_MULT_DOSStub_6127 {
  strings:
    $key_6127 = { 35 4f [2] 41 57 [2] 06 55 [2] 41 44 [2] 0f 48 [2] 03 42 [2] 14 49 [2] 0f 07 [2] 32 }

  condition:
    any of them
}