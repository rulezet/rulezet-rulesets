rule TTP_XOR_MULT_DOSStub_ce68 {
  strings:
    $key_ce68 = { 9a 00 [2] ee 18 [2] a9 1a [2] ee 0b [2] a0 07 [2] ac 0d [2] bb 06 [2] a0 48 [2] 9d }

  condition:
    any of them
}