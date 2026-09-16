rule TTP_XOR_MULT_DOSStub_1eac {
  strings:
    $key_1eac = { 4a c4 [2] 3e dc [2] 79 de [2] 3e cf [2] 70 c3 [2] 7c c9 [2] 6b c2 [2] 70 8c [2] 4d }

  condition:
    any of them
}