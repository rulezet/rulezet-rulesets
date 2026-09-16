rule TTP_XOR_MULT_DOSStub_ce1d {
  strings:
    $key_ce1d = { 9a 75 [2] ee 6d [2] a9 6f [2] ee 7e [2] a0 72 [2] ac 78 [2] bb 73 [2] a0 3d [2] 9d }

  condition:
    any of them
}