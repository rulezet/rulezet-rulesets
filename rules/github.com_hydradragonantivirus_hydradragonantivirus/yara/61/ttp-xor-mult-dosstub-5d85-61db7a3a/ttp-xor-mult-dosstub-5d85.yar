rule TTP_XOR_MULT_DOSStub_5d85 {
  strings:
    $key_5d85 = { 09 ed [2] 7d f5 [2] 3a f7 [2] 7d e6 [2] 33 ea [2] 3f e0 [2] 28 eb [2] 33 a5 [2] 0e }

  condition:
    any of them
}