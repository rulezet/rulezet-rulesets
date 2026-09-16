rule TTP_XOR_MULT_DOSStub_5c1a {
  strings:
    $key_5c1a = { 08 72 [2] 7c 6a [2] 3b 68 [2] 7c 79 [2] 32 75 [2] 3e 7f [2] 29 74 [2] 32 3a [2] 0f }

  condition:
    any of them
}