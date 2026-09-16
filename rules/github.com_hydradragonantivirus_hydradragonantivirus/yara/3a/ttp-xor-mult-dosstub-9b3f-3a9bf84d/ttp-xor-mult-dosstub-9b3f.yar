rule TTP_XOR_MULT_DOSStub_9b3f {
  strings:
    $key_9b3f = { cf 57 [2] bb 4f [2] fc 4d [2] bb 5c [2] f5 50 [2] f9 5a [2] ee 51 [2] f5 1f [2] c8 }

  condition:
    any of them
}