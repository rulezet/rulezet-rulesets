rule TTP_XOR_MULT_DOSStub_ce38 {
  strings:
    $key_ce38 = { 9a 50 [2] ee 48 [2] a9 4a [2] ee 5b [2] a0 57 [2] ac 5d [2] bb 56 [2] a0 18 [2] 9d }

  condition:
    any of them
}