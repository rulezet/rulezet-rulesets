rule TTP_XOR_MULT_DOSStub_5c0a {
  strings:
    $key_5c0a = { 08 62 [2] 7c 7a [2] 3b 78 [2] 7c 69 [2] 32 65 [2] 3e 6f [2] 29 64 [2] 32 2a [2] 0f }

  condition:
    any of them
}