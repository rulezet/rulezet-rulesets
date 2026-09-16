rule TTP_XOR_MULT_DOSStub_5c05 {
  strings:
    $key_5c05 = { 08 6d [2] 7c 75 [2] 3b 77 [2] 7c 66 [2] 32 6a [2] 3e 60 [2] 29 6b [2] 32 25 [2] 0f }

  condition:
    any of them
}