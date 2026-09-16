rule TTP_XOR_MULT_DOSStub_69aa {
  strings:
    $key_69aa = { 3d c2 [2] 49 da [2] 0e d8 [2] 49 c9 [2] 07 c5 [2] 0b cf [2] 1c c4 [2] 07 8a [2] 3a }

  condition:
    any of them
}