rule TTP_XOR_MULT_DOSStub_9b6c {
  strings:
    $key_9b6c = { cf 04 [2] bb 1c [2] fc 1e [2] bb 0f [2] f5 03 [2] f9 09 [2] ee 02 [2] f5 4c [2] c8 }

  condition:
    any of them
}