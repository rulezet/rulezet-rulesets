rule TTP_XOR_MULT_DOSStub_5c78 {
  strings:
    $key_5c78 = { 08 10 [2] 7c 08 [2] 3b 0a [2] 7c 1b [2] 32 17 [2] 3e 1d [2] 29 16 [2] 32 58 [2] 0f }

  condition:
    any of them
}