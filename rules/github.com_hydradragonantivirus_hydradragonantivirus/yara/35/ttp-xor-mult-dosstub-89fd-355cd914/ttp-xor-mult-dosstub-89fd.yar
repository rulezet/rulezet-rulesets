rule TTP_XOR_MULT_DOSStub_89fd {
  strings:
    $key_89fd = { dd 95 [2] a9 8d [2] ee 8f [2] a9 9e [2] e7 92 [2] eb 98 [2] fc 93 [2] e7 dd [2] da }

  condition:
    any of them
}