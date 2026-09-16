rule TTP_XOR_MULT_DOSStub_6188 {
  strings:
    $key_6188 = { 35 e0 [2] 41 f8 [2] 06 fa [2] 41 eb [2] 0f e7 [2] 03 ed [2] 14 e6 [2] 0f a8 [2] 32 }

  condition:
    any of them
}