rule TTP_XOR_MULT_DOSStub_ce4b {
  strings:
    $key_ce4b = { 9a 23 [2] ee 3b [2] a9 39 [2] ee 28 [2] a0 24 [2] ac 2e [2] bb 25 [2] a0 6b [2] 9d }

  condition:
    any of them
}