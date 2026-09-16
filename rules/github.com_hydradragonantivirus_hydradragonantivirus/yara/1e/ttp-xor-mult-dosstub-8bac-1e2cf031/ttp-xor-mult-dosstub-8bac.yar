rule TTP_XOR_MULT_DOSStub_8bac {
  strings:
    $key_8bac = { df c4 [2] ab dc [2] ec de [2] ab cf [2] e5 c3 [2] e9 c9 [2] fe c2 [2] e5 8c [2] d8 }

  condition:
    any of them
}