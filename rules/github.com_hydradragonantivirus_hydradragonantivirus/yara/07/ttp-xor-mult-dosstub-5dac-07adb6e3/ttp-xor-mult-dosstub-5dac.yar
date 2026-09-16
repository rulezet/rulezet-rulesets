rule TTP_XOR_MULT_DOSStub_5dac {
  strings:
    $key_5dac = { 09 c4 [2] 7d dc [2] 3a de [2] 7d cf [2] 33 c3 [2] 3f c9 [2] 28 c2 [2] 33 8c [2] 0e }

  condition:
    any of them
}