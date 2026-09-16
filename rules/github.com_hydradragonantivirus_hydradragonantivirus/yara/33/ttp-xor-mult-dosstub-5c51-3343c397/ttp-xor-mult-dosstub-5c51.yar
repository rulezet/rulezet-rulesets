rule TTP_XOR_MULT_DOSStub_5c51 {
  strings:
    $key_5c51 = { 08 39 [2] 7c 21 [2] 3b 23 [2] 7c 32 [2] 32 3e [2] 3e 34 [2] 29 3f [2] 32 71 [2] 0f }

  condition:
    any of them
}