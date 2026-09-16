rule TTP_XOR_MULT_DOSStub_ce2a {
  strings:
    $key_ce2a = { 9a 42 [2] ee 5a [2] a9 58 [2] ee 49 [2] a0 45 [2] ac 4f [2] bb 44 [2] a0 0a [2] 9d }

  condition:
    any of them
}