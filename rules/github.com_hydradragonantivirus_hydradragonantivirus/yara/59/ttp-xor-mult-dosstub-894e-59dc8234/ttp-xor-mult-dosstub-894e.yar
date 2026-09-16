rule TTP_XOR_MULT_DOSStub_894e {
  strings:
    $key_894e = { dd 26 [2] a9 3e [2] ee 3c [2] a9 2d [2] e7 21 [2] eb 2b [2] fc 20 [2] e7 6e [2] da }

  condition:
    any of them
}