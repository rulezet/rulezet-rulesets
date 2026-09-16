rule TTP_XOR_MULT_DOSStub_5c69 {
  strings:
    $key_5c69 = { 08 01 [2] 7c 19 [2] 3b 1b [2] 7c 0a [2] 32 06 [2] 3e 0c [2] 29 07 [2] 32 49 [2] 0f }

  condition:
    any of them
}