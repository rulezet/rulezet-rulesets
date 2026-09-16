rule TTP_XOR_MULT_DOSStub_1e06 {
  strings:
    $key_1e06 = { 4a 6e [2] 3e 76 [2] 79 74 [2] 3e 65 [2] 70 69 [2] 7c 63 [2] 6b 68 [2] 70 26 [2] 4d }

  condition:
    any of them
}