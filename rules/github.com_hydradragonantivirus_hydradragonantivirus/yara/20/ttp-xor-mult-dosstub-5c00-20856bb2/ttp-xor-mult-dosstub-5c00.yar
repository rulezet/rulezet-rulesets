rule TTP_XOR_MULT_DOSStub_5c00 {
  strings:
    $key_5c00 = { 08 68 [2] 7c 70 [2] 3b 72 [2] 7c 63 [2] 32 6f [2] 3e 65 [2] 29 6e [2] 32 20 [2] 0f }

  condition:
    any of them
}