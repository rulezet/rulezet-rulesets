rule TTP_XOR_MULT_DOSStub_891f {
  strings:
    $key_891f = { dd 77 [2] a9 6f [2] ee 6d [2] a9 7c [2] e7 70 [2] eb 7a [2] fc 71 [2] e7 3f [2] da }

  condition:
    any of them
}