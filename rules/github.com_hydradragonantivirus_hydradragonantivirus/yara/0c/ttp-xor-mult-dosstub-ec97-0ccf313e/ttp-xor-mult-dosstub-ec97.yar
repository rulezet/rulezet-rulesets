rule TTP_XOR_MULT_DOSStub_ec97 {
  strings:
    $key_ec97 = { b8 ff [2] cc e7 [2] 8b e5 [2] cc f4 [2] 82 f8 [2] 8e f2 [2] 99 f9 [2] 82 b7 [2] bf }

  condition:
    any of them
}