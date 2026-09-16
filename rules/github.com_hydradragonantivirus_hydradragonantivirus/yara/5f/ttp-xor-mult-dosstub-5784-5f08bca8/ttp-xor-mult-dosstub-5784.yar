rule TTP_XOR_MULT_DOSStub_5784 {
  strings:
    $key_5784 = { 03 ec [2] 77 f4 [2] 30 f6 [2] 77 e7 [2] 39 eb [2] 35 e1 [2] 22 ea [2] 39 a4 [2] 04 }

  condition:
    any of them
}