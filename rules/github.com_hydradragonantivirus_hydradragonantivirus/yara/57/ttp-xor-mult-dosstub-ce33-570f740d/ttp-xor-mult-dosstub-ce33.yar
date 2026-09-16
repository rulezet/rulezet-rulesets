rule TTP_XOR_MULT_DOSStub_ce33 {
  strings:
    $key_ce33 = { 9a 5b [2] ee 43 [2] a9 41 [2] ee 50 [2] a0 5c [2] ac 56 [2] bb 5d [2] a0 13 [2] 9d }

  condition:
    any of them
}