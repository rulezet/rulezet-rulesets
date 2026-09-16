rule TTP_XOR_MULT_DOSStub_2283 {
  strings:
    $key_2283 = { 76 eb [2] 02 f3 [2] 45 f1 [2] 02 e0 [2] 4c ec [2] 40 e6 [2] 57 ed [2] 4c a3 [2] 71 }

  condition:
    any of them
}