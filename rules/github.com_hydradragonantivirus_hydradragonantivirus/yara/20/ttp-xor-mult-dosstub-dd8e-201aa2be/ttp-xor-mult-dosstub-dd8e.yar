rule TTP_XOR_MULT_DOSStub_dd8e {
  strings:
    $key_dd8e = { 89 e6 [2] fd fe [2] ba fc [2] fd ed [2] b3 e1 [2] bf eb [2] a8 e0 [2] b3 ae [2] 8e }

  condition:
    any of them
}