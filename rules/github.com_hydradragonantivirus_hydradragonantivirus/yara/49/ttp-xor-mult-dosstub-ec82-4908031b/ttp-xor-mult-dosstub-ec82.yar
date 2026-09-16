rule TTP_XOR_MULT_DOSStub_ec82 {
  strings:
    $key_ec82 = { b8 ea [2] cc f2 [2] 8b f0 [2] cc e1 [2] 82 ed [2] 8e e7 [2] 99 ec [2] 82 a2 [2] bf }

  condition:
    any of them
}