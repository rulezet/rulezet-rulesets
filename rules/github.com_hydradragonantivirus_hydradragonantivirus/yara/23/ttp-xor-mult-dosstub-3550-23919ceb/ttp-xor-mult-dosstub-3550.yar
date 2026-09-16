rule TTP_XOR_MULT_DOSStub_3550 {
  strings:
    $key_3550 = { 61 38 [2] 15 20 [2] 52 22 [2] 15 33 [2] 5b 3f [2] 57 35 [2] 40 3e [2] 5b 70 [2] 66 }

  condition:
    any of them
}