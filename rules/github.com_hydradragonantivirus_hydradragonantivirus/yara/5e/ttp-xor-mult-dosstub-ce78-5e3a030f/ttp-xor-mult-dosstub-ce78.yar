rule TTP_XOR_MULT_DOSStub_ce78 {
  strings:
    $key_ce78 = { 9a 10 [2] ee 08 [2] a9 0a [2] ee 1b [2] a0 17 [2] ac 1d [2] bb 16 [2] a0 58 [2] 9d }

  condition:
    any of them
}