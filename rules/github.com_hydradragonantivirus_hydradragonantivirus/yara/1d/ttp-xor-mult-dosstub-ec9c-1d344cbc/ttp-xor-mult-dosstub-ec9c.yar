rule TTP_XOR_MULT_DOSStub_ec9c {
  strings:
    $key_ec9c = { b8 f4 [2] cc ec [2] 8b ee [2] cc ff [2] 82 f3 [2] 8e f9 [2] 99 f2 [2] 82 bc [2] bf }

  condition:
    any of them
}