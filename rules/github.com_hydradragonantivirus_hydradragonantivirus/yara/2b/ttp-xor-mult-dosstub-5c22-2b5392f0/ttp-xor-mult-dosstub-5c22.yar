rule TTP_XOR_MULT_DOSStub_5c22 {
  strings:
    $key_5c22 = { 08 4a [2] 7c 52 [2] 3b 50 [2] 7c 41 [2] 32 4d [2] 3e 47 [2] 29 4c [2] 32 02 [2] 0f }

  condition:
    any of them
}