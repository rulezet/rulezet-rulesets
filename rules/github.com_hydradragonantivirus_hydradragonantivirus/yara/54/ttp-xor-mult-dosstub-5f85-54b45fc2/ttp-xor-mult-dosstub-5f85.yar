rule TTP_XOR_MULT_DOSStub_5f85 {
  strings:
    $key_5f85 = { 0b ed [2] 7f f5 [2] 38 f7 [2] 7f e6 [2] 31 ea [2] 3d e0 [2] 2a eb [2] 31 a5 [2] 0c }

  condition:
    any of them
}