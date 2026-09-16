rule TTP_XOR_MULT_DOSStub_57b1 {
  strings:
    $key_57b1 = { 03 d9 [2] 77 c1 [2] 30 c3 [2] 77 d2 [2] 39 de [2] 35 d4 [2] 22 df [2] 39 91 [2] 04 }

  condition:
    any of them
}