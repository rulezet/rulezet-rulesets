rule TTP_XOR_MULT_DOSStub_ce28 {
  strings:
    $key_ce28 = { 9a 40 [2] ee 58 [2] a9 5a [2] ee 4b [2] a0 47 [2] ac 4d [2] bb 46 [2] a0 08 [2] 9d }

  condition:
    any of them
}