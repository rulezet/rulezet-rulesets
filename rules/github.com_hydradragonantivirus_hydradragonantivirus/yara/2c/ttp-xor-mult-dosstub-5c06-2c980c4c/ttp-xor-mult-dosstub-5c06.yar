rule TTP_XOR_MULT_DOSStub_5c06 {
  strings:
    $key_5c06 = { 08 6e [2] 7c 76 [2] 3b 74 [2] 7c 65 [2] 32 69 [2] 3e 63 [2] 29 68 [2] 32 26 [2] 0f }

  condition:
    any of them
}