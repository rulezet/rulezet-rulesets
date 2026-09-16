rule TTP_XOR_MULT_DOSStub_5c56 {
  strings:
    $key_5c56 = { 08 3e [2] 7c 26 [2] 3b 24 [2] 7c 35 [2] 32 39 [2] 3e 33 [2] 29 38 [2] 32 76 [2] 0f }

  condition:
    any of them
}