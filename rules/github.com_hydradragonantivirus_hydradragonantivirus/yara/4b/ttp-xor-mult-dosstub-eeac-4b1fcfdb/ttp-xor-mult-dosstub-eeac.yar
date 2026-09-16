rule TTP_XOR_MULT_DOSStub_eeac {
  strings:
    $key_eeac = { ba c4 [2] ce dc [2] 89 de [2] ce cf [2] 80 c3 [2] 8c c9 [2] 9b c2 [2] 80 8c [2] bd }

  condition:
    any of them
}