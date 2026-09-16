rule TTP_XOR_MULT_DOSStub_ce49 {
  strings:
    $key_ce49 = { 9a 21 [2] ee 39 [2] a9 3b [2] ee 2a [2] a0 26 [2] ac 2c [2] bb 27 [2] a0 69 [2] 9d }

  condition:
    any of them
}