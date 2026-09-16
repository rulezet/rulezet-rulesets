rule TTP_XOR_MULT_DOSStub_7083 {
  strings:
    $key_7083 = { 24 eb [2] 50 f3 [2] 17 f1 [2] 50 e0 [2] 1e ec [2] 12 e6 [2] 05 ed [2] 1e a3 [2] 23 }

  condition:
    any of them
}