rule TTP_XOR_MULT_DOSStub_2688 {
  strings:
    $key_2688 = { 72 e0 [2] 06 f8 [2] 41 fa [2] 06 eb [2] 48 e7 [2] 44 ed [2] 53 e6 [2] 48 a8 [2] 75 }

  condition:
    any of them
}