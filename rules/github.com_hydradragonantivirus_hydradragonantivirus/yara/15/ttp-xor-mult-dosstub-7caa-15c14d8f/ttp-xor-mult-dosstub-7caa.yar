rule TTP_XOR_MULT_DOSStub_7caa {
  strings:
    $key_7caa = { 28 c2 [2] 5c da [2] 1b d8 [2] 5c c9 [2] 12 c5 [2] 1e cf [2] 09 c4 [2] 12 8a [2] 2f }

  condition:
    any of them
}