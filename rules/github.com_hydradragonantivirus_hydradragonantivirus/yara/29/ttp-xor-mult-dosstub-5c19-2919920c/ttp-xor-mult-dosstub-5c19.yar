rule TTP_XOR_MULT_DOSStub_5c19 {
  strings:
    $key_5c19 = { 08 71 [2] 7c 69 [2] 3b 6b [2] 7c 7a [2] 32 76 [2] 3e 7c [2] 29 77 [2] 32 39 [2] 0f }

  condition:
    any of them
}