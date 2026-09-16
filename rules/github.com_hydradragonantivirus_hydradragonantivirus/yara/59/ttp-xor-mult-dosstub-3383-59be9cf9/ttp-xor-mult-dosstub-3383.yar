rule TTP_XOR_MULT_DOSStub_3383 {
  strings:
    $key_3383 = { 67 eb [2] 13 f3 [2] 54 f1 [2] 13 e0 [2] 5d ec [2] 51 e6 [2] 46 ed [2] 5d a3 [2] 60 }

  condition:
    any of them
}