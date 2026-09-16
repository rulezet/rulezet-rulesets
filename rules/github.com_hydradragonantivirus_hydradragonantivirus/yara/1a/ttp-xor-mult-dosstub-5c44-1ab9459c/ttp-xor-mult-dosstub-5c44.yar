rule TTP_XOR_MULT_DOSStub_5c44 {
  strings:
    $key_5c44 = { 08 2c [2] 7c 34 [2] 3b 36 [2] 7c 27 [2] 32 2b [2] 3e 21 [2] 29 2a [2] 32 64 [2] 0f }

  condition:
    any of them
}