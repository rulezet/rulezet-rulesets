rule TTP_XOR_MULT_DOSStub_5c61 {
  strings:
    $key_5c61 = { 08 09 [2] 7c 11 [2] 3b 13 [2] 7c 02 [2] 32 0e [2] 3e 04 [2] 29 0f [2] 32 41 [2] 0f }

  condition:
    any of them
}