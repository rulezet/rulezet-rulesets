rule TTP_XOR_MULT_DOSStub_89ea {
  strings:
    $key_89ea = { dd 82 [2] a9 9a [2] ee 98 [2] a9 89 [2] e7 85 [2] eb 8f [2] fc 84 [2] e7 ca [2] da }

  condition:
    any of them
}