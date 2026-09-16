rule TTP_XOR_MULT_DOSStub_5c74 {
  strings:
    $key_5c74 = { 08 1c [2] 7c 04 [2] 3b 06 [2] 7c 17 [2] 32 1b [2] 3e 11 [2] 29 1a [2] 32 54 [2] 0f }

  condition:
    any of them
}