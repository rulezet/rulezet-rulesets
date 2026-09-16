rule TTP_XOR_MULT_DOSStub_ce51 {
  strings:
    $key_ce51 = { 9a 39 [2] ee 21 [2] a9 23 [2] ee 32 [2] a0 3e [2] ac 34 [2] bb 3f [2] a0 71 [2] 9d }

  condition:
    any of them
}