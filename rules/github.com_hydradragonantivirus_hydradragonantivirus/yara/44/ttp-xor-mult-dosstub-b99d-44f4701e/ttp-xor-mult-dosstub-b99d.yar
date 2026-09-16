rule TTP_XOR_MULT_DOSStub_b99d {
  strings:
    $key_b99d = { ed f5 [2] 99 ed [2] de ef [2] 99 fe [2] d7 f2 [2] db f8 [2] cc f3 [2] d7 bd [2] ea }

  condition:
    any of them
}