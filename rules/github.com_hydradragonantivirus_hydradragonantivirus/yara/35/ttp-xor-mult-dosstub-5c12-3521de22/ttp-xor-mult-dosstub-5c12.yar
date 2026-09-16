rule TTP_XOR_MULT_DOSStub_5c12 {
  strings:
    $key_5c12 = { 08 7a [2] 7c 62 [2] 3b 60 [2] 7c 71 [2] 32 7d [2] 3e 77 [2] 29 7c [2] 32 32 [2] 0f }

  condition:
    any of them
}