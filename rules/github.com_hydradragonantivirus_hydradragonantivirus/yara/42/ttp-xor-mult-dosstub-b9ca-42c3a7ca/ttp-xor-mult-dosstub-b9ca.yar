rule TTP_XOR_MULT_DOSStub_b9ca {
  strings:
    $key_b9ca = { ed a2 [2] 99 ba [2] de b8 [2] 99 a9 [2] d7 a5 [2] db af [2] cc a4 [2] d7 ea [2] ea }

  condition:
    any of them
}