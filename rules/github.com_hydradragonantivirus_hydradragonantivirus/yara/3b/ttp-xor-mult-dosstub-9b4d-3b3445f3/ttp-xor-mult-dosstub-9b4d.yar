rule TTP_XOR_MULT_DOSStub_9b4d {
  strings:
    $key_9b4d = { cf 25 [2] bb 3d [2] fc 3f [2] bb 2e [2] f5 22 [2] f9 28 [2] ee 23 [2] f5 6d [2] c8 }

  condition:
    any of them
}