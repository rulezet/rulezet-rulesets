rule TTP_XOR_MULT_DOSStub_6d85 {
  strings:
    $key_6d85 = { 39 ed [2] 4d f5 [2] 0a f7 [2] 4d e6 [2] 03 ea [2] 0f e0 [2] 18 eb [2] 03 a5 [2] 3e }

  condition:
    any of them
}