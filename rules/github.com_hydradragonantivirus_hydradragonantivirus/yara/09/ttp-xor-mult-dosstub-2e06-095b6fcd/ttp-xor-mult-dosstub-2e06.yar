rule TTP_XOR_MULT_DOSStub_2e06 {
  strings:
    $key_2e06 = { 7a 6e [2] 0e 76 [2] 49 74 [2] 0e 65 [2] 40 69 [2] 4c 63 [2] 5b 68 [2] 40 26 [2] 7d }

  condition:
    any of them
}