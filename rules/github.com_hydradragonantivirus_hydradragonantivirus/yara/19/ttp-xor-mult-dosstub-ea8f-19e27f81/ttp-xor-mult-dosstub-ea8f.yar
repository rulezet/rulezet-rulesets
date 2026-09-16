rule TTP_XOR_MULT_DOSStub_ea8f {
  strings:
    $key_ea8f = { be e7 [2] ca ff [2] 8d fd [2] ca ec [2] 84 e0 [2] 88 ea [2] 9f e1 [2] 84 af [2] b9 }

  condition:
    any of them
}