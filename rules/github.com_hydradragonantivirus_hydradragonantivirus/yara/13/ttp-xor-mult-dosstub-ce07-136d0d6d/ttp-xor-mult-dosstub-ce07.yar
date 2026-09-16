rule TTP_XOR_MULT_DOSStub_ce07 {
  strings:
    $key_ce07 = { 9a 6f [2] ee 77 [2] a9 75 [2] ee 64 [2] a0 68 [2] ac 62 [2] bb 69 [2] a0 27 [2] 9d }

  condition:
    any of them
}