rule TTP_XOR_MULT_DOSStub_ea85 {
  strings:
    $key_ea85 = { be ed [2] ca f5 [2] 8d f7 [2] ca e6 [2] 84 ea [2] 88 e0 [2] 9f eb [2] 84 a5 [2] b9 }

  condition:
    any of them
}