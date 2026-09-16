rule TTP_XOR_MULT_DOSStub_89d9 {
  strings:
    $key_89d9 = { dd b1 [2] a9 a9 [2] ee ab [2] a9 ba [2] e7 b6 [2] eb bc [2] fc b7 [2] e7 f9 [2] da }

  condition:
    any of them
}