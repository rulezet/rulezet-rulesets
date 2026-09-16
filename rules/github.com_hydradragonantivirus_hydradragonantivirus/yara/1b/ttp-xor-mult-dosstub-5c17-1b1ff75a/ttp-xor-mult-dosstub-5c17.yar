rule TTP_XOR_MULT_DOSStub_5c17 {
  strings:
    $key_5c17 = { 08 7f [2] 7c 67 [2] 3b 65 [2] 7c 74 [2] 32 78 [2] 3e 72 [2] 29 79 [2] 32 37 [2] 0f }

  condition:
    any of them
}