rule TTP_XOR_MULT_DOSStub_7dac {
  strings:
    $key_7dac = { 29 c4 [2] 5d dc [2] 1a de [2] 5d cf [2] 13 c3 [2] 1f c9 [2] 08 c2 [2] 13 8c [2] 2e }

  condition:
    any of them
}