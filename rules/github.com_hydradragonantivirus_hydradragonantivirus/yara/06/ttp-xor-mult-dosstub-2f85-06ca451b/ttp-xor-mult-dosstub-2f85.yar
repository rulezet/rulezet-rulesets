rule TTP_XOR_MULT_DOSStub_2f85 {
  strings:
    $key_2f85 = { 7b ed [2] 0f f5 [2] 48 f7 [2] 0f e6 [2] 41 ea [2] 4d e0 [2] 5a eb [2] 41 a5 [2] 7c }

  condition:
    any of them
}