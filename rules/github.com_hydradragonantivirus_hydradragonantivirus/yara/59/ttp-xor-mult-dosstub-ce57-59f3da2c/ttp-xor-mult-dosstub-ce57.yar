rule TTP_XOR_MULT_DOSStub_ce57 {
  strings:
    $key_ce57 = { 9a 3f [2] ee 27 [2] a9 25 [2] ee 34 [2] a0 38 [2] ac 32 [2] bb 39 [2] a0 77 [2] 9d }

  condition:
    any of them
}