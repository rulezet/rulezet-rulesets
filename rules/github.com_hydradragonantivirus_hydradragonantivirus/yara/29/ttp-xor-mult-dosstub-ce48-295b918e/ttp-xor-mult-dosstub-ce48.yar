rule TTP_XOR_MULT_DOSStub_ce48 {
  strings:
    $key_ce48 = { 9a 20 [2] ee 38 [2] a9 3a [2] ee 2b [2] a0 27 [2] ac 2d [2] bb 26 [2] a0 68 [2] 9d }

  condition:
    any of them
}