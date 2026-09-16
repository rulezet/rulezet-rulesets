rule TTP_XOR_MULT_DOSStub_b98d {
  strings:
    $key_b98d = { ed e5 [2] 99 fd [2] de ff [2] 99 ee [2] d7 e2 [2] db e8 [2] cc e3 [2] d7 ad [2] ea }

  condition:
    any of them
}