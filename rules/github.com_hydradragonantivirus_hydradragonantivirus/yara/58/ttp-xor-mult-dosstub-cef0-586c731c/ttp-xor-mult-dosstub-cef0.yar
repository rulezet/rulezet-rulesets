rule TTP_XOR_MULT_DOSStub_cef0 {
  strings:
    $key_cef0 = { 9a 98 [2] ee 80 [2] a9 82 [2] ee 93 [2] a0 9f [2] ac 95 [2] bb 9e [2] a0 d0 [2] 9d }

  condition:
    any of them
}