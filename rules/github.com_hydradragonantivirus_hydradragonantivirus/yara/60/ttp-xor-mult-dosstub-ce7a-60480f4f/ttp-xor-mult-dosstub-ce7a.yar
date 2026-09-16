rule TTP_XOR_MULT_DOSStub_ce7a {
  strings:
    $key_ce7a = { 9a 12 [2] ee 0a [2] a9 08 [2] ee 19 [2] a0 15 [2] ac 1f [2] bb 14 [2] a0 5a [2] 9d }

  condition:
    any of them
}