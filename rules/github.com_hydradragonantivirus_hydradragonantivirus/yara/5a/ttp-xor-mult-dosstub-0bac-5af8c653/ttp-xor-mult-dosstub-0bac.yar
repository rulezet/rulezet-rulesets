rule TTP_XOR_MULT_DOSStub_0bac {
  strings:
    $key_0bac = { 5f c4 [2] 2b dc [2] 6c de [2] 2b cf [2] 65 c3 [2] 69 c9 [2] 7e c2 [2] 65 8c [2] 58 }

  condition:
    any of them
}