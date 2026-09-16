rule TTP_XOR_MULT_DOSStub_4aac {
  strings:
    $key_4aac = { 1e c4 [2] 6a dc [2] 2d de [2] 6a cf [2] 24 c3 [2] 28 c9 [2] 3f c2 [2] 24 8c [2] 19 }

  condition:
    any of them
}