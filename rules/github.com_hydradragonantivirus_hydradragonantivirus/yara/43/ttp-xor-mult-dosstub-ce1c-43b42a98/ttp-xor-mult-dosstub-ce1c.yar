rule TTP_XOR_MULT_DOSStub_ce1c {
  strings:
    $key_ce1c = { 9a 74 [2] ee 6c [2] a9 6e [2] ee 7f [2] a0 73 [2] ac 79 [2] bb 72 [2] a0 3c [2] 9d }

  condition:
    any of them
}