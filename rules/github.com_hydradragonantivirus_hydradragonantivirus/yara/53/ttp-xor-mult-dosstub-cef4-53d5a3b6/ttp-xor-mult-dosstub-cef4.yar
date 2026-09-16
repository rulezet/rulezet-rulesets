rule TTP_XOR_MULT_DOSStub_cef4 {
  strings:
    $key_cef4 = { 9a 9c [2] ee 84 [2] a9 86 [2] ee 97 [2] a0 9b [2] ac 91 [2] bb 9a [2] a0 d4 [2] 9d }

  condition:
    any of them
}