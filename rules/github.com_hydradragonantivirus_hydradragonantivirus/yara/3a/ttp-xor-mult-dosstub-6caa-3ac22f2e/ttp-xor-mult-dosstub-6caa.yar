rule TTP_XOR_MULT_DOSStub_6caa {
  strings:
    $key_6caa = { 38 c2 [2] 4c da [2] 0b d8 [2] 4c c9 [2] 02 c5 [2] 0e cf [2] 19 c4 [2] 02 8a [2] 3f }

  condition:
    any of them
}