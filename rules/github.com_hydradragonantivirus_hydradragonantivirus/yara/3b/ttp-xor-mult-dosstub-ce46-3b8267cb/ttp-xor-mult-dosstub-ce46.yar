rule TTP_XOR_MULT_DOSStub_ce46 {
  strings:
    $key_ce46 = { 9a 2e [2] ee 36 [2] a9 34 [2] ee 25 [2] a0 29 [2] ac 23 [2] bb 28 [2] a0 66 [2] 9d }

  condition:
    any of them
}