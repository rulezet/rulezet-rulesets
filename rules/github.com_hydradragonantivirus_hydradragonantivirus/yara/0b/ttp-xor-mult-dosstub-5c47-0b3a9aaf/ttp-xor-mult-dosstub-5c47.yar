rule TTP_XOR_MULT_DOSStub_5c47 {
  strings:
    $key_5c47 = { 08 2f [2] 7c 37 [2] 3b 35 [2] 7c 24 [2] 32 28 [2] 3e 22 [2] 29 29 [2] 32 67 [2] 0f }

  condition:
    any of them
}