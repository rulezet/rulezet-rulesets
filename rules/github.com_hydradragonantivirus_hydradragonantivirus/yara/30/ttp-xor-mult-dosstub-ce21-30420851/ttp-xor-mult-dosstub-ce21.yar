rule TTP_XOR_MULT_DOSStub_ce21 {
  strings:
    $key_ce21 = { 9a 49 [2] ee 51 [2] a9 53 [2] ee 42 [2] a0 4e [2] ac 44 [2] bb 4f [2] a0 01 [2] 9d }

  condition:
    any of them
}