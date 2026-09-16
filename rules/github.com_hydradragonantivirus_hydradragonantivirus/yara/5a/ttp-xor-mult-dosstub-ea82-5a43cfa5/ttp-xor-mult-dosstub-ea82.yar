rule TTP_XOR_MULT_DOSStub_ea82 {
  strings:
    $key_ea82 = { be ea [2] ca f2 [2] 8d f0 [2] ca e1 [2] 84 ed [2] 88 e7 [2] 9f ec [2] 84 a2 [2] b9 }

  condition:
    any of them
}