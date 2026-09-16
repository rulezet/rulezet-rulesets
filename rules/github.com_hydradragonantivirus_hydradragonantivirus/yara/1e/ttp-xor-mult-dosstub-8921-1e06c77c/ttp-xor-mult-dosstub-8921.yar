rule TTP_XOR_MULT_DOSStub_8921 {
  strings:
    $key_8921 = { dd 49 [2] a9 51 [2] ee 53 [2] a9 42 [2] e7 4e [2] eb 44 [2] fc 4f [2] e7 01 [2] da }

  condition:
    any of them
}