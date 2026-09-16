rule TTP_XOR_MULT_DOSStub_e88f {
  strings:
    $key_e88f = { bc e7 [2] c8 ff [2] 8f fd [2] c8 ec [2] 86 e0 [2] 8a ea [2] 9d e1 [2] 86 af [2] bb }

  condition:
    any of them
}