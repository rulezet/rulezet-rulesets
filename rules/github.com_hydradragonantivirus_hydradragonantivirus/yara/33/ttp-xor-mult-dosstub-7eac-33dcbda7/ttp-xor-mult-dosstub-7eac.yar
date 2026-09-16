rule TTP_XOR_MULT_DOSStub_7eac {
  strings:
    $key_7eac = { 2a c4 [2] 5e dc [2] 19 de [2] 5e cf [2] 10 c3 [2] 1c c9 [2] 0b c2 [2] 10 8c [2] 2d }

  condition:
    any of them
}