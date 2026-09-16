rule TTP_XOR_MULT_DOSStub_7383 {
  strings:
    $key_7383 = { 27 eb [2] 53 f3 [2] 14 f1 [2] 53 e0 [2] 1d ec [2] 11 e6 [2] 06 ed [2] 1d a3 [2] 20 }

  condition:
    any of them
}