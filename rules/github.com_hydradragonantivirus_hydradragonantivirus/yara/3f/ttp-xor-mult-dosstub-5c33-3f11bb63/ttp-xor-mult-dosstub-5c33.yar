rule TTP_XOR_MULT_DOSStub_5c33 {
  strings:
    $key_5c33 = { 08 5b [2] 7c 43 [2] 3b 41 [2] 7c 50 [2] 32 5c [2] 3e 56 [2] 29 5d [2] 32 13 [2] 0f }

  condition:
    any of them
}