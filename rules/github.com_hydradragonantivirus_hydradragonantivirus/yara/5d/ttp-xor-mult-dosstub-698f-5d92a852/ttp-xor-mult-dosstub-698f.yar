rule TTP_XOR_MULT_DOSStub_698f {
  strings:
    $key_698f = { 3d e7 [2] 49 ff [2] 0e fd [2] 49 ec [2] 07 e0 [2] 0b ea [2] 1c e1 [2] 07 af [2] 3a }

  condition:
    any of them
}