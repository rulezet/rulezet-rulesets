rule TTP_XOR_MULT_DOSStub_8986 {
  strings:
    $key_8986 = { dd ee [2] a9 f6 [2] ee f4 [2] a9 e5 [2] e7 e9 [2] eb e3 [2] fc e8 [2] e7 a6 [2] da }

  condition:
    any of them
}