rule TTP_XOR_MULT_DOSStub_891c {
  strings:
    $key_891c = { dd 74 [2] a9 6c [2] ee 6e [2] a9 7f [2] e7 73 [2] eb 79 [2] fc 72 [2] e7 3c [2] da }

  condition:
    any of them
}