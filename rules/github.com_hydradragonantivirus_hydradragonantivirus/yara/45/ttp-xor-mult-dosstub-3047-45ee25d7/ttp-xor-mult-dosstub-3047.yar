rule TTP_XOR_MULT_DOSStub_3047 {
  strings:
    $key_3047 = { 64 2f [2] 10 37 [2] 57 35 [2] 10 24 [2] 5e 28 [2] 52 22 [2] 45 29 [2] 5e 67 [2] 63 }

  condition:
    any of them
}