rule TTP_XOR_MULT_DOSStub_9b9a {
  strings:
    $key_9b9a = { cf f2 [2] bb ea [2] fc e8 [2] bb f9 [2] f5 f5 [2] f9 ff [2] ee f4 [2] f5 ba [2] c8 }

  condition:
    any of them
}