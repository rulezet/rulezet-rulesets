rule TTP_XOR_MULT_DOSStub_5c68 {
  strings:
    $key_5c68 = { 08 00 [2] 7c 18 [2] 3b 1a [2] 7c 0b [2] 32 07 [2] 3e 0d [2] 29 06 [2] 32 48 [2] 0f }

  condition:
    any of them
}