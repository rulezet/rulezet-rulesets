rule TTP_XOR_MULT_DOSStub_e98d {
  strings:
    $key_e98d = { bd e5 [2] c9 fd [2] 8e ff [2] c9 ee [2] 87 e2 [2] 8b e8 [2] 9c e3 [2] 87 ad [2] ba }

  condition:
    any of them
}