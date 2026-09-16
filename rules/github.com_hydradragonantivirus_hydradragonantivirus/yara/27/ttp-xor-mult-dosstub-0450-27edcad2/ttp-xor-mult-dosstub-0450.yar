rule TTP_XOR_MULT_DOSStub_0450 {
  strings:
    $key_0450 = { 50 38 [2] 24 20 [2] 63 22 [2] 24 33 [2] 6a 3f [2] 66 35 [2] 71 3e [2] 6a 70 [2] 57 }

  condition:
    any of them
}