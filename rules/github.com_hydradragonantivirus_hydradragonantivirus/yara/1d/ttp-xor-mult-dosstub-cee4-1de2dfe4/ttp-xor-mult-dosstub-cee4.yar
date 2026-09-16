rule TTP_XOR_MULT_DOSStub_cee4 {
  strings:
    $key_cee4 = { 9a 8c [2] ee 94 [2] a9 96 [2] ee 87 [2] a0 8b [2] ac 81 [2] bb 8a [2] a0 c4 [2] 9d }

  condition:
    any of them
}