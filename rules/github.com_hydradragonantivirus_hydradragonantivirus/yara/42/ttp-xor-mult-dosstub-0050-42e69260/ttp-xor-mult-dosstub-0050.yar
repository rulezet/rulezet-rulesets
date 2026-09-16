rule TTP_XOR_MULT_DOSStub_0050 {
  strings:
    $key_0050 = { 54 38 [2] 20 20 [2] 67 22 [2] 20 33 [2] 6e 3f [2] 62 35 [2] 75 3e [2] 6e 70 [2] 53 }

  condition:
    any of them
}