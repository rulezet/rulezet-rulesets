rule TTP_XOR_MULT_DOSStub_ce18 {
  strings:
    $key_ce18 = { 9a 70 [2] ee 68 [2] a9 6a [2] ee 7b [2] a0 77 [2] ac 7d [2] bb 76 [2] a0 38 [2] 9d }

  condition:
    any of them
}