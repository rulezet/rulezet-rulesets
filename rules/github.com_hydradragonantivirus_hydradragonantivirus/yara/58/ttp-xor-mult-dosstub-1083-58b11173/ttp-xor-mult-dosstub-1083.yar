rule TTP_XOR_MULT_DOSStub_1083 {
  strings:
    $key_1083 = { 44 eb [2] 30 f3 [2] 77 f1 [2] 30 e0 [2] 7e ec [2] 72 e6 [2] 65 ed [2] 7e a3 [2] 43 }

  condition:
    any of them
}