rule TTP_XOR_MULT_DOSStub_9b58 {
  strings:
    $key_9b58 = { cf 30 [2] bb 28 [2] fc 2a [2] bb 3b [2] f5 37 [2] f9 3d [2] ee 36 [2] f5 78 [2] c8 }

  condition:
    any of them
}