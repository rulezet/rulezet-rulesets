rule TTP_XOR_MULT_DOSStub_b985 {
  strings:
    $key_b985 = { ed ed [2] 99 f5 [2] de f7 [2] 99 e6 [2] d7 ea [2] db e0 [2] cc eb [2] d7 a5 [2] ea }

  condition:
    any of them
}