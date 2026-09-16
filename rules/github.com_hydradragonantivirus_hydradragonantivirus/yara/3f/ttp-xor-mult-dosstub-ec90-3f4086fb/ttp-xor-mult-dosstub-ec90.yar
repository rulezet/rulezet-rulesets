rule TTP_XOR_MULT_DOSStub_ec90 {
  strings:
    $key_ec90 = { b8 f8 [2] cc e0 [2] 8b e2 [2] cc f3 [2] 82 ff [2] 8e f5 [2] 99 fe [2] 82 b0 [2] bf }

  condition:
    any of them
}