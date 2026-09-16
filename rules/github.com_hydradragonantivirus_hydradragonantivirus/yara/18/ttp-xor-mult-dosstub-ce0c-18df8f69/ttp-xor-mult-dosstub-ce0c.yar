rule TTP_XOR_MULT_DOSStub_ce0c {
  strings:
    $key_ce0c = { 9a 64 [2] ee 7c [2] a9 7e [2] ee 6f [2] a0 63 [2] ac 69 [2] bb 62 [2] a0 2c [2] 9d }

  condition:
    any of them
}