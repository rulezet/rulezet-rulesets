rule TTP_XOR_MULT_DOSStub_2eac {
  strings:
    $key_2eac = { 7a c4 [2] 0e dc [2] 49 de [2] 0e cf [2] 40 c3 [2] 4c c9 [2] 5b c2 [2] 40 8c [2] 7d }

  condition:
    any of them
}