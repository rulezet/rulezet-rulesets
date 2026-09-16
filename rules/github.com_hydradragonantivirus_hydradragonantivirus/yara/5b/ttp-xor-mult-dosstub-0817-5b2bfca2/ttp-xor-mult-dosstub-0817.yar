rule TTP_XOR_MULT_DOSStub_0817 {
  strings:
    $key_0817 = { 5c 7f [2] 28 67 [2] 6f 65 [2] 28 74 [2] 66 78 [2] 6a 72 [2] 7d 79 [2] 66 37 [2] 5b }

  condition:
    any of them
}