rule TTP_XOR_MULT_DOSStub_5c40 {
  strings:
    $key_5c40 = { 08 28 [2] 7c 30 [2] 3b 32 [2] 7c 23 [2] 32 2f [2] 3e 25 [2] 29 2e [2] 32 60 [2] 0f }

  condition:
    any of them
}