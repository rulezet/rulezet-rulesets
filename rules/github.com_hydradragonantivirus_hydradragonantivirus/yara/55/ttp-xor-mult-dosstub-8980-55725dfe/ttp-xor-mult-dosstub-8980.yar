rule TTP_XOR_MULT_DOSStub_8980 {
  strings:
    $key_8980 = { dd e8 [2] a9 f0 [2] ee f2 [2] a9 e3 [2] e7 ef [2] eb e5 [2] fc ee [2] e7 a0 [2] da }

  condition:
    any of them
}