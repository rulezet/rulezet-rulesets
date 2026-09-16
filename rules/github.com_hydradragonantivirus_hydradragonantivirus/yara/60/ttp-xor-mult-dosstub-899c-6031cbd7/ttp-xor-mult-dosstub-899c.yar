rule TTP_XOR_MULT_DOSStub_899c {
  strings:
    $key_899c = { dd f4 [2] a9 ec [2] ee ee [2] a9 ff [2] e7 f3 [2] eb f9 [2] fc f2 [2] e7 bc [2] da }

  condition:
    any of them
}