rule TTP_XOR_MULT_DOSStub_6783 {
  strings:
    $key_6783 = { 33 eb [2] 47 f3 [2] 00 f1 [2] 47 e0 [2] 09 ec [2] 05 e6 [2] 12 ed [2] 09 a3 [2] 34 }

  condition:
    any of them
}