rule TTP_XOR_MULT_DOSStub_488f {
  strings:
    $key_488f = { 1c e7 [2] 68 ff [2] 2f fd [2] 68 ec [2] 26 e0 [2] 2a ea [2] 3d e1 [2] 26 af [2] 1b }

  condition:
    any of them
}