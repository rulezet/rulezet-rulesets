rule TTP_XOR_MULT_DOSStub_ec8f {
  strings:
    $key_ec8f = { b8 e7 [2] cc ff [2] 8b fd [2] cc ec [2] 82 e0 [2] 8e ea [2] 99 e1 [2] 82 af [2] bf }

  condition:
    any of them
}