rule TTP_XOR_MULT_DOSStub_ce09 {
  strings:
    $key_ce09 = { 9a 61 [2] ee 79 [2] a9 7b [2] ee 6a [2] a0 66 [2] ac 6c [2] bb 67 [2] a0 29 [2] 9d }

  condition:
    any of them
}