rule TTP_XOR_MULT_DOSStub_2d85 {
  strings:
    $key_2d85 = { 79 ed [2] 0d f5 [2] 4a f7 [2] 0d e6 [2] 43 ea [2] 4f e0 [2] 58 eb [2] 43 a5 [2] 7e }

  condition:
    any of them
}