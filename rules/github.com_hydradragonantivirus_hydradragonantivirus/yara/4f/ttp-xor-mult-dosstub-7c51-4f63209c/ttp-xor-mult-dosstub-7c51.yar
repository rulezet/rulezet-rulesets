rule TTP_XOR_MULT_DOSStub_7c51 {
  strings:
    $key_7c51 = { 28 39 [2] 5c 21 [2] 1b 23 [2] 5c 32 [2] 12 3e [2] 1e 34 [2] 09 3f [2] 12 71 [2] 2f }

  condition:
    any of them
}