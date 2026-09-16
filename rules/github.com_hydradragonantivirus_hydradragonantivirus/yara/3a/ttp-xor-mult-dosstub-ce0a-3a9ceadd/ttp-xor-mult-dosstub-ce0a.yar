rule TTP_XOR_MULT_DOSStub_ce0a {
  strings:
    $key_ce0a = { 9a 62 [2] ee 7a [2] a9 78 [2] ee 69 [2] a0 65 [2] ac 6f [2] bb 64 [2] a0 2a [2] 9d }

  condition:
    any of them
}