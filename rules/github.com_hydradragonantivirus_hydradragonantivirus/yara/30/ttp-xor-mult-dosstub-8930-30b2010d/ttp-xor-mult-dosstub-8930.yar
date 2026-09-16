rule TTP_XOR_MULT_DOSStub_8930 {
  strings:
    $key_8930 = { dd 58 [2] a9 40 [2] ee 42 [2] a9 53 [2] e7 5f [2] eb 55 [2] fc 5e [2] e7 10 [2] da }

  condition:
    any of them
}