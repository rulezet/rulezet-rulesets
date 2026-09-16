rule TTP_XOR_MULT_DOSStub_2caa {
  strings:
    $key_2caa = { 78 c2 [2] 0c da [2] 4b d8 [2] 0c c9 [2] 42 c5 [2] 4e cf [2] 59 c4 [2] 42 8a [2] 7f }

  condition:
    any of them
}