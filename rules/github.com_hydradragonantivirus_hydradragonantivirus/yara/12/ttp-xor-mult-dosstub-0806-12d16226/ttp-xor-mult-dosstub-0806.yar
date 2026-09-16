rule TTP_XOR_MULT_DOSStub_0806 {
  strings:
    $key_0806 = { 5c 6e [2] 28 76 [2] 6f 74 [2] 28 65 [2] 66 69 [2] 6a 63 [2] 7d 68 [2] 66 26 [2] 5b }

  condition:
    any of them
}