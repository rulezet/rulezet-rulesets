rule TTP_XOR_MULT_DOSStub_ce16 {
  strings:
    $key_ce16 = { 9a 7e [2] ee 66 [2] a9 64 [2] ee 75 [2] a0 79 [2] ac 73 [2] bb 78 [2] a0 36 [2] 9d }

  condition:
    any of them
}