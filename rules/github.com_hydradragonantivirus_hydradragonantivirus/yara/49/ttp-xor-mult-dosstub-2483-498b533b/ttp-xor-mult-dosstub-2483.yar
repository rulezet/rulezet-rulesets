rule TTP_XOR_MULT_DOSStub_2483 {
  strings:
    $key_2483 = { 70 eb [2] 04 f3 [2] 43 f1 [2] 04 e0 [2] 4a ec [2] 46 e6 [2] 51 ed [2] 4a a3 [2] 77 }

  condition:
    any of them
}