rule TTP_XOR_MULT_DOSStub_ce27 {
  strings:
    $key_ce27 = { 9a 4f [2] ee 57 [2] a9 55 [2] ee 44 [2] a0 48 [2] ac 42 [2] bb 49 [2] a0 07 [2] 9d }

  condition:
    any of them
}