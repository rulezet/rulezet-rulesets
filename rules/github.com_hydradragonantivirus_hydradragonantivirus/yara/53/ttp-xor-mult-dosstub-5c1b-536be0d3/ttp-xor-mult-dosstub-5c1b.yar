rule TTP_XOR_MULT_DOSStub_5c1b {
  strings:
    $key_5c1b = { 08 73 [2] 7c 6b [2] 3b 69 [2] 7c 78 [2] 32 74 [2] 3e 7e [2] 29 75 [2] 32 3b [2] 0f }

  condition:
    any of them
}