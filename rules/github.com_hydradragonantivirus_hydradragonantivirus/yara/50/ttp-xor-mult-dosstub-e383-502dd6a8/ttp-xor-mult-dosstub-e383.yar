rule TTP_XOR_MULT_DOSStub_e383 {
  strings:
    $key_e383 = { b7 eb [2] c3 f3 [2] 84 f1 [2] c3 e0 [2] 8d ec [2] 81 e6 [2] 96 ed [2] 8d a3 [2] b0 }

  condition:
    any of them
}