rule TTP_XOR_MULT_DOSStub_ce26 {
  strings:
    $key_ce26 = { 9a 4e [2] ee 56 [2] a9 54 [2] ee 45 [2] a0 49 [2] ac 43 [2] bb 48 [2] a0 06 [2] 9d }

  condition:
    any of them
}