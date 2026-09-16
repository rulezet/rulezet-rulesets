rule TTP_XOR_MULT_DOSStub_89ce {
  strings:
    $key_89ce = { dd a6 [2] a9 be [2] ee bc [2] a9 ad [2] e7 a1 [2] eb ab [2] fc a0 [2] e7 ee [2] da }

  condition:
    any of them
}