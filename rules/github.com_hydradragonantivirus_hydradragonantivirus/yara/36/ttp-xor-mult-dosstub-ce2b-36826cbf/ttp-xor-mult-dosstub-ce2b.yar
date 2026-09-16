rule TTP_XOR_MULT_DOSStub_ce2b {
  strings:
    $key_ce2b = { 9a 43 [2] ee 5b [2] a9 59 [2] ee 48 [2] a0 44 [2] ac 4e [2] bb 45 [2] a0 0b [2] 9d }

  condition:
    any of them
}