rule TTP_XOR_MULT_DOSStub_ce73 {
  strings:
    $key_ce73 = { 9a 1b [2] ee 03 [2] a9 01 [2] ee 10 [2] a0 1c [2] ac 16 [2] bb 1d [2] a0 53 [2] 9d }

  condition:
    any of them
}