rule TTP_XOR_MULT_DOSStub_e98f {
  strings:
    $key_e98f = { bd e7 [2] c9 ff [2] 8e fd [2] c9 ec [2] 87 e0 [2] 8b ea [2] 9c e1 [2] 87 af [2] ba }

  condition:
    any of them
}