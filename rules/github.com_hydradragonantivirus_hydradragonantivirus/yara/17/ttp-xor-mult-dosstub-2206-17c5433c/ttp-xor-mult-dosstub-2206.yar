rule TTP_XOR_MULT_DOSStub_2206 {
  strings:
    $key_2206 = { 76 6e [2] 02 76 [2] 45 74 [2] 02 65 [2] 4c 69 [2] 40 63 [2] 57 68 [2] 4c 26 [2] 71 }

  condition:
    any of them
}