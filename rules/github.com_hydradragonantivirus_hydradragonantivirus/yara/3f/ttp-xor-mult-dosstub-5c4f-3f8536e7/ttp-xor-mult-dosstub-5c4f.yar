rule TTP_XOR_MULT_DOSStub_5c4f {
  strings:
    $key_5c4f = { 08 27 [2] 7c 3f [2] 3b 3d [2] 7c 2c [2] 32 20 [2] 3e 2a [2] 29 21 [2] 32 6f [2] 0f }

  condition:
    any of them
}