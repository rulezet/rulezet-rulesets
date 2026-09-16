rule TTP_XOR_MULT_DOSStub_5c32 {
  strings:
    $key_5c32 = { 08 5a [2] 7c 42 [2] 3b 40 [2] 7c 51 [2] 32 5d [2] 3e 57 [2] 29 5c [2] 32 12 [2] 0f }

  condition:
    any of them
}