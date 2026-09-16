rule TTP_XOR_MULT_DOSStub_89a2 {
  strings:
    $key_89a2 = { dd ca [2] a9 d2 [2] ee d0 [2] a9 c1 [2] e7 cd [2] eb c7 [2] fc cc [2] e7 82 [2] da }

  condition:
    any of them
}