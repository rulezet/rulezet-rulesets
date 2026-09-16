rule TTP_XOR_MULT_DOSStub_5c24 {
  strings:
    $key_5c24 = { 08 4c [2] 7c 54 [2] 3b 56 [2] 7c 47 [2] 32 4b [2] 3e 41 [2] 29 4a [2] 32 04 [2] 0f }

  condition:
    any of them
}