rule TTP_XOR_MULT_DOSStub_6d88 {
  strings:
    $key_6d88 = { 39 e0 [2] 4d f8 [2] 0a fa [2] 4d eb [2] 03 e7 [2] 0f ed [2] 18 e6 [2] 03 a8 [2] 3e }

  condition:
    any of them
}