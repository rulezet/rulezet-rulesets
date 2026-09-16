rule TTP_XOR_MULT_DOSStub_ce24 {
  strings:
    $key_ce24 = { 9a 4c [2] ee 54 [2] a9 56 [2] ee 47 [2] a0 4b [2] ac 41 [2] bb 4a [2] a0 04 [2] 9d }

  condition:
    any of them
}