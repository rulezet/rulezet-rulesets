rule TTP_XOR_MULT_DOSStub_8966 {
  strings:
    $key_8966 = { dd 0e [2] a9 16 [2] ee 14 [2] a9 05 [2] e7 09 [2] eb 03 [2] fc 08 [2] e7 46 [2] da }

  condition:
    any of them
}