rule TTP_XOR_MULT_DOSStub_3f85 {
  strings:
    $key_3f85 = { 6b ed [2] 1f f5 [2] 58 f7 [2] 1f e6 [2] 51 ea [2] 5d e0 [2] 4a eb [2] 51 a5 [2] 6c }

  condition:
    any of them
}