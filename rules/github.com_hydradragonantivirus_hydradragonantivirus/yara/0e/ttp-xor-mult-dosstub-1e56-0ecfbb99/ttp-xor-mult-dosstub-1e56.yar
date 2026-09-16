rule TTP_XOR_MULT_DOSStub_1e56 {
  strings:
    $key_1e56 = { 4a 3e [2] 3e 26 [2] 79 24 [2] 3e 35 [2] 70 39 [2] 7c 33 [2] 6b 38 [2] 70 76 [2] 4d }

  condition:
    any of them
}