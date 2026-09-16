rule TTP_XOR_MULT_DOSStub_2383 {
  strings:
    $key_2383 = { 77 eb [2] 03 f3 [2] 44 f1 [2] 03 e0 [2] 4d ec [2] 41 e6 [2] 56 ed [2] 4d a3 [2] 70 }

  condition:
    any of them
}