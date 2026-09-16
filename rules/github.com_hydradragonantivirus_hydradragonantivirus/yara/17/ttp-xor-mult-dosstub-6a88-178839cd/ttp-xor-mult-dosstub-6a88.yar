rule TTP_XOR_MULT_DOSStub_6a88 {
  strings:
    $key_6a88 = { 3e e0 [2] 4a f8 [2] 0d fa [2] 4a eb [2] 04 e7 [2] 08 ed [2] 1f e6 [2] 04 a8 [2] 39 }

  condition:
    any of them
}