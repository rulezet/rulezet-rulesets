rule TTP_XOR_MULT_DOSStub_fe88 {
  strings:
    $key_fe88 = { aa e0 [2] de f8 [2] 99 fa [2] de eb [2] 90 e7 [2] 9c ed [2] 8b e6 [2] 90 a8 [2] ad }

  condition:
    any of them
}