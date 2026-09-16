rule TTP_XOR_MULT_DOSStub_0383 {
  strings:
    $key_0383 = { 57 eb [2] 23 f3 [2] 64 f1 [2] 23 e0 [2] 6d ec [2] 61 e6 [2] 76 ed [2] 6d a3 [2] 50 }

  condition:
    any of them
}