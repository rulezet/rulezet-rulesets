rule TTP_XOR_MULT_DOSStub_89c8 {
  strings:
    $key_89c8 = { dd a0 [2] a9 b8 [2] ee ba [2] a9 ab [2] e7 a7 [2] eb ad [2] fc a6 [2] e7 e8 [2] da }

  condition:
    any of them
}