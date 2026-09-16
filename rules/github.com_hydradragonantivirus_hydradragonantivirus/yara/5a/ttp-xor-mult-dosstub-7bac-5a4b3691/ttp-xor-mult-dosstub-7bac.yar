rule TTP_XOR_MULT_DOSStub_7bac {
  strings:
    $key_7bac = { 2f c4 [2] 5b dc [2] 1c de [2] 5b cf [2] 15 c3 [2] 19 c9 [2] 0e c2 [2] 15 8c [2] 28 }

  condition:
    any of them
}