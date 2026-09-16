rule TTP_XOR_MULT_DOSStub_8e8f {
  strings:
    $key_8e8f = { da e7 [2] ae ff [2] e9 fd [2] ae ec [2] e0 e0 [2] ec ea [2] fb e1 [2] e0 af [2] dd }

  condition:
    any of them
}