rule TTP_XOR_MULT_DOSStub_cf8e {
  strings:
    $key_cf8e = { 9b e6 [2] ef fe [2] a8 fc [2] ef ed [2] a1 e1 [2] ad eb [2] ba e0 [2] a1 ae [2] 9c }

  condition:
    any of them
}