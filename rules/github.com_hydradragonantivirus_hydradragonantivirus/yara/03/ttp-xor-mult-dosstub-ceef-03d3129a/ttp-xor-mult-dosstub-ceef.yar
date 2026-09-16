rule TTP_XOR_MULT_DOSStub_ceef {
  strings:
    $key_ceef = { 9a 87 [2] ee 9f [2] a9 9d [2] ee 8c [2] a0 80 [2] ac 8a [2] bb 81 [2] a0 cf [2] 9d }

  condition:
    any of them
}