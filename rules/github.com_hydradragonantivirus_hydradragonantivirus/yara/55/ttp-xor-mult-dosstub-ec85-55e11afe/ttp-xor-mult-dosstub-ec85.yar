rule TTP_XOR_MULT_DOSStub_ec85 {
  strings:
    $key_ec85 = { b8 ed [2] cc f5 [2] 8b f7 [2] cc e6 [2] 82 ea [2] 8e e0 [2] 99 eb [2] 82 a5 [2] bf }

  condition:
    any of them
}