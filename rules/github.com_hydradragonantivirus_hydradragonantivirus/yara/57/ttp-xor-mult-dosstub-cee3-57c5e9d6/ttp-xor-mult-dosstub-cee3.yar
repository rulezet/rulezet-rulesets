rule TTP_XOR_MULT_DOSStub_cee3 {
  strings:
    $key_cee3 = { 9a 8b [2] ee 93 [2] a9 91 [2] ee 80 [2] a0 8c [2] ac 86 [2] bb 8d [2] a0 c3 [2] 9d }

  condition:
    any of them
}