rule TTP_XOR_MULT_DOSStub_ceee {
  strings:
    $key_ceee = { 9a 86 [2] ee 9e [2] a9 9c [2] ee 8d [2] a0 81 [2] ac 8b [2] bb 80 [2] a0 ce [2] 9d }

  condition:
    any of them
}