rule TTP_XOR_MULT_DOSStub_61bb {
  strings:
    $key_61bb = { 35 d3 [2] 41 cb [2] 06 c9 [2] 41 d8 [2] 0f d4 [2] 03 de [2] 14 d5 [2] 0f 9b [2] 32 }

  condition:
    any of them
}