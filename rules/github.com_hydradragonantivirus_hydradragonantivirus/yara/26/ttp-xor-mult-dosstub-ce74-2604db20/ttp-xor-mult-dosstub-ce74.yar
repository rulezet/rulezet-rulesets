rule TTP_XOR_MULT_DOSStub_ce74 {
  strings:
    $key_ce74 = { 9a 1c [2] ee 04 [2] a9 06 [2] ee 17 [2] a0 1b [2] ac 11 [2] bb 1a [2] a0 54 [2] 9d }

  condition:
    any of them
}