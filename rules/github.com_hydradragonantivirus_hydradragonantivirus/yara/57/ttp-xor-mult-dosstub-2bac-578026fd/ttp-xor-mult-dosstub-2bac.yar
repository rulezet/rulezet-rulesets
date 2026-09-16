rule TTP_XOR_MULT_DOSStub_2bac {
  strings:
    $key_2bac = { 7f c4 [2] 0b dc [2] 4c de [2] 0b cf [2] 45 c3 [2] 49 c9 [2] 5e c2 [2] 45 8c [2] 78 }

  condition:
    any of them
}