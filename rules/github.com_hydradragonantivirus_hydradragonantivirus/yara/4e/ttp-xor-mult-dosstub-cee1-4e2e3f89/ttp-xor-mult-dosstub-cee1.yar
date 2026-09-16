rule TTP_XOR_MULT_DOSStub_cee1 {
  strings:
    $key_cee1 = { 9a 89 [2] ee 91 [2] a9 93 [2] ee 82 [2] a0 8e [2] ac 84 [2] bb 8f [2] a0 c1 [2] 9d }

  condition:
    any of them
}