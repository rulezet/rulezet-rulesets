rule TTP_XOR_MULT_DOSStub_9b1d {
  strings:
    $key_9b1d = { cf 75 [2] bb 6d [2] fc 6f [2] bb 7e [2] f5 72 [2] f9 78 [2] ee 73 [2] f5 3d [2] c8 }

  condition:
    any of them
}