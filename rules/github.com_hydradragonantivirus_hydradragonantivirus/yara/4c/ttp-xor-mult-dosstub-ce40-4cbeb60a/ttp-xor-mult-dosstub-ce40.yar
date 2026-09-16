rule TTP_XOR_MULT_DOSStub_ce40 {
  strings:
    $key_ce40 = { 9a 28 [2] ee 30 [2] a9 32 [2] ee 23 [2] a0 2f [2] ac 25 [2] bb 2e [2] a0 60 [2] 9d }

  condition:
    any of them
}