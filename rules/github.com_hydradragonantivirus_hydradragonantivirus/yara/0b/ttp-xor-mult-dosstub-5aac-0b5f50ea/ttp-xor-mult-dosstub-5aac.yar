rule TTP_XOR_MULT_DOSStub_5aac {
  strings:
    $key_5aac = { 0e c4 [2] 7a dc [2] 3d de [2] 7a cf [2] 34 c3 [2] 38 c9 [2] 2f c2 [2] 34 8c [2] 09 }

  condition:
    any of them
}