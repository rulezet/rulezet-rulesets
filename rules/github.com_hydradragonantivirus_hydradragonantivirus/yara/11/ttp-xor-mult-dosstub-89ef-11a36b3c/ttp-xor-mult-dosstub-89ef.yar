rule TTP_XOR_MULT_DOSStub_89ef {
  strings:
    $key_89ef = { dd 87 [2] a9 9f [2] ee 9d [2] a9 8c [2] e7 80 [2] eb 8a [2] fc 81 [2] e7 cf [2] da }

  condition:
    any of them
}