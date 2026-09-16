rule TTP_XOR_MULT_DOSStub_6bac {
  strings:
    $key_6bac = { 3f c4 [2] 4b dc [2] 0c de [2] 4b cf [2] 05 c3 [2] 09 c9 [2] 1e c2 [2] 05 8c [2] 38 }

  condition:
    any of them
}