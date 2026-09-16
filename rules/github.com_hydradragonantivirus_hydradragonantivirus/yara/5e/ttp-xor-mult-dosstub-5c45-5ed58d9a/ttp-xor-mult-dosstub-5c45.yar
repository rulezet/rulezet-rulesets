rule TTP_XOR_MULT_DOSStub_5c45 {
  strings:
    $key_5c45 = { 08 2d [2] 7c 35 [2] 3b 37 [2] 7c 26 [2] 32 2a [2] 3e 20 [2] 29 2b [2] 32 65 [2] 0f }

  condition:
    any of them
}