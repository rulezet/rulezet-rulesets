rule TTP_XOR_MULT_DOSStub_8953 {
  strings:
    $key_8953 = { dd 3b [2] a9 23 [2] ee 21 [2] a9 30 [2] e7 3c [2] eb 36 [2] fc 3d [2] e7 73 [2] da }

  condition:
    any of them
}