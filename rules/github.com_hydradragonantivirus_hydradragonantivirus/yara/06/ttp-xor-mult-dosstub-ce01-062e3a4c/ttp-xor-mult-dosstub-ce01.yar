rule TTP_XOR_MULT_DOSStub_ce01 {
  strings:
    $key_ce01 = { 9a 69 [2] ee 71 [2] a9 73 [2] ee 62 [2] a0 6e [2] ac 64 [2] bb 6f [2] a0 21 [2] 9d }

  condition:
    any of them
}