rule TTP_XOR_MULT_DOSStub_5c59 {
  strings:
    $key_5c59 = { 08 31 [2] 7c 29 [2] 3b 2b [2] 7c 3a [2] 32 36 [2] 3e 3c [2] 29 37 [2] 32 79 [2] 0f }

  condition:
    any of them
}