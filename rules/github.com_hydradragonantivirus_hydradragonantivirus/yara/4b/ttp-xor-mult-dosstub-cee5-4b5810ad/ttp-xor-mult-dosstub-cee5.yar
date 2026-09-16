rule TTP_XOR_MULT_DOSStub_cee5 {
  strings:
    $key_cee5 = { 9a 8d [2] ee 95 [2] a9 97 [2] ee 86 [2] a0 8a [2] ac 80 [2] bb 8b [2] a0 c5 [2] 9d }

  condition:
    any of them
}