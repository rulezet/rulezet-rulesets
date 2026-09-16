rule TTP_XOR_MULT_DOSStub_890c {
  strings:
    $key_890c = { dd 64 [2] a9 7c [2] ee 7e [2] a9 6f [2] e7 63 [2] eb 69 [2] fc 62 [2] e7 2c [2] da }

  condition:
    any of them
}