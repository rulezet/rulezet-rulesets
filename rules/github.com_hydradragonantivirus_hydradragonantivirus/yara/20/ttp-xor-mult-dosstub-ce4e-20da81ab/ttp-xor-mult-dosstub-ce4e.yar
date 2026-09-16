rule TTP_XOR_MULT_DOSStub_ce4e {
  strings:
    $key_ce4e = { 9a 26 [2] ee 3e [2] a9 3c [2] ee 2d [2] a0 21 [2] ac 2b [2] bb 20 [2] a0 6e [2] 9d }

  condition:
    any of them
}