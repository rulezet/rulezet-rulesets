rule TTP_XOR_MULT_DOSStub_9b5f {
  strings:
    $key_9b5f = { cf 37 [2] bb 2f [2] fc 2d [2] bb 3c [2] f5 30 [2] f9 3a [2] ee 31 [2] f5 7f [2] c8 }

  condition:
    any of them
}