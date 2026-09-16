rule TTP_XOR_MULT_DOSStub_5c2d {
  strings:
    $key_5c2d = { 08 45 [2] 7c 5d [2] 3b 5f [2] 7c 4e [2] 32 42 [2] 3e 48 [2] 29 43 [2] 32 0d [2] 0f }

  condition:
    any of them
}