rule TTP_XOR_MULT_DOSStub_89a7 {
  strings:
    $key_89a7 = { dd cf [2] a9 d7 [2] ee d5 [2] a9 c4 [2] e7 c8 [2] eb c2 [2] fc c9 [2] e7 87 [2] da }

  condition:
    any of them
}