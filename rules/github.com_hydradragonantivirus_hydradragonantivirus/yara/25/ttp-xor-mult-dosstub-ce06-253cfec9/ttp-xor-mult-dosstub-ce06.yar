rule TTP_XOR_MULT_DOSStub_ce06 {
  strings:
    $key_ce06 = { 9a 6e [2] ee 76 [2] a9 74 [2] ee 65 [2] a0 69 [2] ac 63 [2] bb 68 [2] a0 26 [2] 9d }

  condition:
    any of them
}