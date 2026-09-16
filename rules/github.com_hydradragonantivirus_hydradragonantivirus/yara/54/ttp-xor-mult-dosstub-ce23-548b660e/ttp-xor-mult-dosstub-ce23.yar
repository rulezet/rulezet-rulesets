rule TTP_XOR_MULT_DOSStub_ce23 {
  strings:
    $key_ce23 = { 9a 4b [2] ee 53 [2] a9 51 [2] ee 40 [2] a0 4c [2] ac 46 [2] bb 4d [2] a0 03 [2] 9d }

  condition:
    any of them
}