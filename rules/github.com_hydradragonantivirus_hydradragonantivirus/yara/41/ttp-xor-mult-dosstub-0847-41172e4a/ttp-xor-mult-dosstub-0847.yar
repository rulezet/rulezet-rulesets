rule TTP_XOR_MULT_DOSStub_0847 {
  strings:
    $key_0847 = { 5c 2f [2] 28 37 [2] 6f 35 [2] 28 24 [2] 66 28 [2] 6a 22 [2] 7d 29 [2] 66 67 [2] 5b }

  condition:
    any of them
}