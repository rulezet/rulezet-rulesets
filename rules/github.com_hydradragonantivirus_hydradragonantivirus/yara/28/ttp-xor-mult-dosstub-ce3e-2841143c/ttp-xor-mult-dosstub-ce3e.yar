rule TTP_XOR_MULT_DOSStub_ce3e {
  strings:
    $key_ce3e = { 9a 56 [2] ee 4e [2] a9 4c [2] ee 5d [2] a0 51 [2] ac 5b [2] bb 50 [2] a0 1e [2] 9d }

  condition:
    any of them
}