rule TTP_XOR_MULT_DOSStub_cef5 {
  strings:
    $key_cef5 = { 9a 9d [2] ee 85 [2] a9 87 [2] ee 96 [2] a0 9a [2] ac 90 [2] bb 9b [2] a0 d5 [2] 9d }

  condition:
    any of them
}