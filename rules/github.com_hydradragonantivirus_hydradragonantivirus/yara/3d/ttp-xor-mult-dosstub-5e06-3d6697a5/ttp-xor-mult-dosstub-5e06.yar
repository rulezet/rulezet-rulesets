rule TTP_XOR_MULT_DOSStub_5e06 {
  strings:
    $key_5e06 = { 0a 6e [2] 7e 76 [2] 39 74 [2] 7e 65 [2] 30 69 [2] 3c 63 [2] 2b 68 [2] 30 26 [2] 0d }

  condition:
    any of them
}