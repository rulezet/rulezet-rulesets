rule TTP_XOR_MULT_DOSStub_ce02 {
  strings:
    $key_ce02 = { 9a 6a [2] ee 72 [2] a9 70 [2] ee 61 [2] a0 6d [2] ac 67 [2] bb 6c [2] a0 22 [2] 9d }

  condition:
    any of them
}