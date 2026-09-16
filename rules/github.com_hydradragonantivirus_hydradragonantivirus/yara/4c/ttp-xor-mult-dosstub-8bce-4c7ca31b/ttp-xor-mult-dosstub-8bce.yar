rule TTP_XOR_MULT_DOSStub_8bce {
  strings:
    $key_8bce = { df a6 [2] ab be [2] ec bc [2] ab ad [2] e5 a1 [2] e9 ab [2] fe a0 [2] e5 ee [2] d8 }

  condition:
    any of them
}