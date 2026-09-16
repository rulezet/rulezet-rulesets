rule TTP_XOR_MULT_DOSStub_5c72 {
  strings:
    $key_5c72 = { 08 1a [2] 7c 02 [2] 3b 00 [2] 7c 11 [2] 32 1d [2] 3e 17 [2] 29 1c [2] 32 52 [2] 0f }

  condition:
    any of them
}