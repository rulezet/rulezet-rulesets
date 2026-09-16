rule TTP_XOR_MULT_DOSStub_0f85 {
  strings:
    $key_0f85 = { 5b ed [2] 2f f5 [2] 68 f7 [2] 2f e6 [2] 61 ea [2] 6d e0 [2] 7a eb [2] 61 a5 [2] 5c }

  condition:
    any of them
}