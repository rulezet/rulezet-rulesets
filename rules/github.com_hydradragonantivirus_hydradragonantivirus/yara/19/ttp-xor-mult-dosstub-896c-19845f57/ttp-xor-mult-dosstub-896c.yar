rule TTP_XOR_MULT_DOSStub_896c {
  strings:
    $key_896c = { dd 04 [2] a9 1c [2] ee 1e [2] a9 0f [2] e7 03 [2] eb 09 [2] fc 02 [2] e7 4c [2] da }

  condition:
    any of them
}