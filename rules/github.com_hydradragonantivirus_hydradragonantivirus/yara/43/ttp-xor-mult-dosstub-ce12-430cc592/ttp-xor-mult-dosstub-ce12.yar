rule TTP_XOR_MULT_DOSStub_ce12 {
  strings:
    $key_ce12 = { 9a 7a [2] ee 62 [2] a9 60 [2] ee 71 [2] a0 7d [2] ac 77 [2] bb 7c [2] a0 32 [2] 9d }

  condition:
    any of them
}