rule TTP_XOR_MULT_DOSStub_89fe {
  strings:
    $key_89fe = { dd 96 [2] a9 8e [2] ee 8c [2] a9 9d [2] e7 91 [2] eb 9b [2] fc 90 [2] e7 de [2] da }

  condition:
    any of them
}