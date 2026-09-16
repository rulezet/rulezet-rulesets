rule TTP_XOR_MULT_DOSStub_5c01 {
  strings:
    $key_5c01 = { 08 69 [2] 7c 71 [2] 3b 73 [2] 7c 62 [2] 32 6e [2] 3e 64 [2] 29 6f [2] 32 21 [2] 0f }

  condition:
    any of them
}