rule TTP_XOR_MULT_DOSStub_e98e {
  strings:
    $key_e98e = { bd e6 [2] c9 fe [2] 8e fc [2] c9 ed [2] 87 e1 [2] 8b eb [2] 9c e0 [2] 87 ae [2] ba }

  condition:
    any of them
}