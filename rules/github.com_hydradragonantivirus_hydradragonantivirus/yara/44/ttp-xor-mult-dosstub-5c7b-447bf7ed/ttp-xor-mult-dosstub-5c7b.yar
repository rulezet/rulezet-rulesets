rule TTP_XOR_MULT_DOSStub_5c7b {
  strings:
    $key_5c7b = { 08 13 [2] 7c 0b [2] 3b 09 [2] 7c 18 [2] 32 14 [2] 3e 1e [2] 29 15 [2] 32 5b [2] 0f }

  condition:
    any of them
}