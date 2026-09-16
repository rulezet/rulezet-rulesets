rule TTP_XOR_MULT_DOSStub_2aac {
  strings:
    $key_2aac = { 7e c4 [2] 0a dc [2] 4d de [2] 0a cf [2] 44 c3 [2] 48 c9 [2] 5f c2 [2] 44 8c [2] 79 }

  condition:
    any of them
}