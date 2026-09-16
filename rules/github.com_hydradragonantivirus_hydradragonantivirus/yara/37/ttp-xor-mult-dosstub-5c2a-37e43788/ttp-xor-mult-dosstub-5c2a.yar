rule TTP_XOR_MULT_DOSStub_5c2a {
  strings:
    $key_5c2a = { 08 42 [2] 7c 5a [2] 3b 58 [2] 7c 49 [2] 32 45 [2] 3e 4f [2] 29 44 [2] 32 0a [2] 0f }

  condition:
    any of them
}