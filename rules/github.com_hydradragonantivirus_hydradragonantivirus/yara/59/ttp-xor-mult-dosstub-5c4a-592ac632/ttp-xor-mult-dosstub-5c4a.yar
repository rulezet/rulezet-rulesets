rule TTP_XOR_MULT_DOSStub_5c4a {
  strings:
    $key_5c4a = { 08 22 [2] 7c 3a [2] 3b 38 [2] 7c 29 [2] 32 25 [2] 3e 2f [2] 29 24 [2] 32 6a [2] 0f }

  condition:
    any of them
}