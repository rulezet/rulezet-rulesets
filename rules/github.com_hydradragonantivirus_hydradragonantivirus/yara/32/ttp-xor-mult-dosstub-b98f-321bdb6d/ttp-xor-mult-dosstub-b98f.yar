rule TTP_XOR_MULT_DOSStub_b98f {
  strings:
    $key_b98f = { ed e7 [2] 99 ff [2] de fd [2] 99 ec [2] d7 e0 [2] db ea [2] cc e1 [2] d7 af [2] ea }

  condition:
    any of them
}