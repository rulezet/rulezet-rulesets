rule TTP_XOR_MULT_DOSStub_f88f {
  strings:
    $key_f88f = { ac e7 [2] d8 ff [2] 9f fd [2] d8 ec [2] 96 e0 [2] 9a ea [2] 8d e1 [2] 96 af [2] ab }

  condition:
    any of them
}