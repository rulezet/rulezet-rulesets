rule TTP_XOR_MULT_DOSStub_ce53 {
  strings:
    $key_ce53 = { 9a 3b [2] ee 23 [2] a9 21 [2] ee 30 [2] a0 3c [2] ac 36 [2] bb 3d [2] a0 73 [2] 9d }

  condition:
    any of them
}