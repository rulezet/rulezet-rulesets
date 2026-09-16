rule TTP_XOR_MULT_DOSStub_ea9e {
  strings:
    $key_ea9e = { be f6 [2] ca ee [2] 8d ec [2] ca fd [2] 84 f1 [2] 88 fb [2] 9f f0 [2] 84 be [2] b9 }

  condition:
    any of them
}