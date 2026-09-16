rule TTP_XOR_MULT_DOSStub_5c70 {
  strings:
    $key_5c70 = { 08 18 [2] 7c 00 [2] 3b 02 [2] 7c 13 [2] 32 1f [2] 3e 15 [2] 29 1e [2] 32 50 [2] 0f }

  condition:
    any of them
}