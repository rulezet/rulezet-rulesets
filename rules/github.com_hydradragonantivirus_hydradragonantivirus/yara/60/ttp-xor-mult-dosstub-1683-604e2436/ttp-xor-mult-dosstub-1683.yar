rule TTP_XOR_MULT_DOSStub_1683 {
  strings:
    $key_1683 = { 42 eb [2] 36 f3 [2] 71 f1 [2] 36 e0 [2] 78 ec [2] 74 e6 [2] 63 ed [2] 78 a3 [2] 45 }

  condition:
    any of them
}