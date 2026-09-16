rule TTP_XOR_MULT_DOSStub_5c6f {
  strings:
    $key_5c6f = { 08 07 [2] 7c 1f [2] 3b 1d [2] 7c 0c [2] 32 00 [2] 3e 0a [2] 29 01 [2] 32 4f [2] 0f }

  condition:
    any of them
}