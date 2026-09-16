rule TTP_XOR_MULT_DOSStub_b99b {
  strings:
    $key_b99b = { ed f3 [2] 99 eb [2] de e9 [2] 99 f8 [2] d7 f4 [2] db fe [2] cc f5 [2] d7 bb [2] ea }

  condition:
    any of them
}