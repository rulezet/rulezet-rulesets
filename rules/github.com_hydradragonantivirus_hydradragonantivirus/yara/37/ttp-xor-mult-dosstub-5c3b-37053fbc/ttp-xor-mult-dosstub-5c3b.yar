rule TTP_XOR_MULT_DOSStub_5c3b {
  strings:
    $key_5c3b = { 08 53 [2] 7c 4b [2] 3b 49 [2] 7c 58 [2] 32 54 [2] 3e 5e [2] 29 55 [2] 32 1b [2] 0f }

  condition:
    any of them
}