rule TTP_XOR_MULT_DOSStub_5c65 {
  strings:
    $key_5c65 = { 08 0d [2] 7c 15 [2] 3b 17 [2] 7c 06 [2] 32 0a [2] 3e 00 [2] 29 0b [2] 32 45 [2] 0f }

  condition:
    any of them
}