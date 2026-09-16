rule TTP_XOR_MULT_DOSStub_8988 {
  strings:
    $key_8988 = { dd e0 [2] a9 f8 [2] ee fa [2] a9 eb [2] e7 e7 [2] eb ed [2] fc e6 [2] e7 a8 [2] da }

  condition:
    any of them
}