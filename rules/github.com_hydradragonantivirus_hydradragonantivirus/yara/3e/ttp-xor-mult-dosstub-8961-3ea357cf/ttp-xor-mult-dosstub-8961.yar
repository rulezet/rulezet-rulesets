rule TTP_XOR_MULT_DOSStub_8961 {
  strings:
    $key_8961 = { dd 09 [2] a9 11 [2] ee 13 [2] a9 02 [2] e7 0e [2] eb 04 [2] fc 0f [2] e7 41 [2] da }

  condition:
    any of them
}