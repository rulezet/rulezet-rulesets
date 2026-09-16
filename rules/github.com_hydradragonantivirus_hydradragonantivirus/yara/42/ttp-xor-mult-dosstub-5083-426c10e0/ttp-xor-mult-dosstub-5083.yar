rule TTP_XOR_MULT_DOSStub_5083 {
  strings:
    $key_5083 = { 04 eb [2] 70 f3 [2] 37 f1 [2] 70 e0 [2] 3e ec [2] 32 e6 [2] 25 ed [2] 3e a3 [2] 03 }

  condition:
    any of them
}