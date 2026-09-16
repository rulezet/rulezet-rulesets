rule TTP_XOR_MULT_DOSStub_ce6e {
  strings:
    $key_ce6e = { 9a 06 [2] ee 1e [2] a9 1c [2] ee 0d [2] a0 01 [2] ac 0b [2] bb 00 [2] a0 4e [2] 9d }

  condition:
    any of them
}