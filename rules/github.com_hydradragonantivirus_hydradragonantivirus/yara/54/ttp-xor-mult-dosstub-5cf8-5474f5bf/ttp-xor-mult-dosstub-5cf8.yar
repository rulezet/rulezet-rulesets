rule TTP_XOR_MULT_DOSStub_5cf8 {
  strings:
    $key_5cf8 = { 08 90 [2] 7c 88 [2] 3b 8a [2] 7c 9b [2] 32 97 [2] 3e 9d [2] 29 96 [2] 32 d8 [2] 0f }

  condition:
    any of them
}