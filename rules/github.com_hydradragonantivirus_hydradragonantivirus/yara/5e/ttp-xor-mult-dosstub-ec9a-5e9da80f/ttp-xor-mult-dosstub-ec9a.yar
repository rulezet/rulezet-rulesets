rule TTP_XOR_MULT_DOSStub_ec9a {
  strings:
    $key_ec9a = { b8 f2 [2] cc ea [2] 8b e8 [2] cc f9 [2] 82 f5 [2] 8e ff [2] 99 f4 [2] 82 ba [2] bf }

  condition:
    any of them
}