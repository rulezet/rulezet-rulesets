rule TTP_XOR_MULT_DOSStub_0dac {
  strings:
    $key_0dac = { 59 c4 [2] 2d dc [2] 6a de [2] 2d cf [2] 63 c3 [2] 6f c9 [2] 78 c2 [2] 63 8c [2] 5e }

  condition:
    any of them
}