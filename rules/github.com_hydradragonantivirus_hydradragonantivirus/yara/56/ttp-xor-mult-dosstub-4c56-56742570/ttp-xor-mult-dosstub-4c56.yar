rule TTP_XOR_MULT_DOSStub_4c56 {
  strings:
    $key_4c56 = { 18 3e [2] 6c 26 [2] 2b 24 [2] 6c 35 [2] 22 39 [2] 2e 33 [2] 39 38 [2] 22 76 [2] 1f }

  condition:
    any of them
}