rule TTP_XOR_MULT_DOSStub_cee7 {
  strings:
    $key_cee7 = { 9a 8f [2] ee 97 [2] a9 95 [2] ee 84 [2] a0 88 [2] ac 82 [2] bb 89 [2] a0 c7 [2] 9d }

  condition:
    any of them
}