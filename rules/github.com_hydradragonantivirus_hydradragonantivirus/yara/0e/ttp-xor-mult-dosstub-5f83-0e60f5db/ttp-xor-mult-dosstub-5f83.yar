rule TTP_XOR_MULT_DOSStub_5f83 {
  strings:
    $key_5f83 = { 0b eb [2] 7f f3 [2] 38 f1 [2] 7f e0 [2] 31 ec [2] 3d e6 [2] 2a ed [2] 31 a3 [2] 0c }

  condition:
    any of them
}