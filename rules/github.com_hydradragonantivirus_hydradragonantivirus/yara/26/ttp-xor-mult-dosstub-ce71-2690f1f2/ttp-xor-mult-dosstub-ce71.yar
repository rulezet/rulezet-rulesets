rule TTP_XOR_MULT_DOSStub_ce71 {
  strings:
    $key_ce71 = { 9a 19 [2] ee 01 [2] a9 03 [2] ee 12 [2] a0 1e [2] ac 14 [2] bb 1f [2] a0 51 [2] 9d }

  condition:
    any of them
}