rule TTP_XOR_MULT_DOSStub_89a9 {
  strings:
    $key_89a9 = { dd c1 [2] a9 d9 [2] ee db [2] a9 ca [2] e7 c6 [2] eb cc [2] fc c7 [2] e7 89 [2] da }

  condition:
    any of them
}