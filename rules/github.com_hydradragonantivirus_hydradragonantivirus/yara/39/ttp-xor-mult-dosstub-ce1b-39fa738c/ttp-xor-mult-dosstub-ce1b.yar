rule TTP_XOR_MULT_DOSStub_ce1b {
  strings:
    $key_ce1b = { 9a 73 [2] ee 6b [2] a9 69 [2] ee 78 [2] a0 74 [2] ac 7e [2] bb 75 [2] a0 3b [2] 9d }

  condition:
    any of them
}