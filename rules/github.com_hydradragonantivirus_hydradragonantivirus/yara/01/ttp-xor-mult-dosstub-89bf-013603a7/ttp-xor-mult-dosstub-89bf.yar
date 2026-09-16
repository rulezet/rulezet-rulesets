rule TTP_XOR_MULT_DOSStub_89bf {
  strings:
    $key_89bf = { dd d7 [2] a9 cf [2] ee cd [2] a9 dc [2] e7 d0 [2] eb da [2] fc d1 [2] e7 9f [2] da }

  condition:
    any of them
}