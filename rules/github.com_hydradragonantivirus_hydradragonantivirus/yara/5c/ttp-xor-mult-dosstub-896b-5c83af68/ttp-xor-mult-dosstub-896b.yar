rule TTP_XOR_MULT_DOSStub_896b {
  strings:
    $key_896b = { dd 03 [2] a9 1b [2] ee 19 [2] a9 08 [2] e7 04 [2] eb 0e [2] fc 05 [2] e7 4b [2] da }

  condition:
    any of them
}