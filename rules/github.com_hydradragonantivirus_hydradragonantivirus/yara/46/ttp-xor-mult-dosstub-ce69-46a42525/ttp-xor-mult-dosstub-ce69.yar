rule TTP_XOR_MULT_DOSStub_ce69 {
  strings:
    $key_ce69 = { 9a 01 [2] ee 19 [2] a9 1b [2] ee 0a [2] a0 06 [2] ac 0c [2] bb 07 [2] a0 49 [2] 9d }

  condition:
    any of them
}