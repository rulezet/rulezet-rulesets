rule TTP_XOR_MULT_DOSStub_ce00 {
  strings:
    $key_ce00 = { 9a 68 [2] ee 70 [2] a9 72 [2] ee 63 [2] a0 6f [2] ac 65 [2] bb 6e [2] a0 20 [2] 9d }

  condition:
    any of them
}