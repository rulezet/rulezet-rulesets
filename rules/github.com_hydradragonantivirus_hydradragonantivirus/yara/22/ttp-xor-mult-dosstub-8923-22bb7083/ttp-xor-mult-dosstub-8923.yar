rule TTP_XOR_MULT_DOSStub_8923 {
  strings:
    $key_8923 = { dd 4b [2] a9 53 [2] ee 51 [2] a9 40 [2] e7 4c [2] eb 46 [2] fc 4d [2] e7 03 [2] da }

  condition:
    any of them
}