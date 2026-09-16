rule TTP_XOR_MULT_DOSStub_1684 {
  strings:
    $key_1684 = { 42 ec [2] 36 f4 [2] 71 f6 [2] 36 e7 [2] 78 eb [2] 74 e1 [2] 63 ea [2] 78 a4 [2] 45 }

  condition:
    any of them
}