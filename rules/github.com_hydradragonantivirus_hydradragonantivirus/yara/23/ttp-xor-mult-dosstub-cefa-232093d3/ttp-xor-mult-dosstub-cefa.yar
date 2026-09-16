rule TTP_XOR_MULT_DOSStub_cefa {
  strings:
    $key_cefa = { 9a 92 [2] ee 8a [2] a9 88 [2] ee 99 [2] a0 95 [2] ac 9f [2] bb 94 [2] a0 da [2] 9d }

  condition:
    any of them
}