rule TTP_XOR_MULT_DOSStub_5c0d {
  strings:
    $key_5c0d = { 08 65 [2] 7c 7d [2] 3b 7f [2] 7c 6e [2] 32 62 [2] 3e 68 [2] 29 63 [2] 32 2d [2] 0f }

  condition:
    any of them
}