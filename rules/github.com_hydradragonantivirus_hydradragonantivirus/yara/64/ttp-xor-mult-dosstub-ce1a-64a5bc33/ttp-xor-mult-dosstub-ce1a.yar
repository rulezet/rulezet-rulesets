rule TTP_XOR_MULT_DOSStub_ce1a {
  strings:
    $key_ce1a = { 9a 72 [2] ee 6a [2] a9 68 [2] ee 79 [2] a0 75 [2] ac 7f [2] bb 74 [2] a0 3a [2] 9d }

  condition:
    any of them
}