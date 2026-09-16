rule TTP_XOR_MULT_DOSStub_cee2 {
  strings:
    $key_cee2 = { 9a 8a [2] ee 92 [2] a9 90 [2] ee 81 [2] a0 8d [2] ac 87 [2] bb 8c [2] a0 c2 [2] 9d }

  condition:
    any of them
}