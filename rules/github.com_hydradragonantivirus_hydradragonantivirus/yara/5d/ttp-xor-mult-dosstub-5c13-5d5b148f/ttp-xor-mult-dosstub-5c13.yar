rule TTP_XOR_MULT_DOSStub_5c13 {
  strings:
    $key_5c13 = { 08 7b [2] 7c 63 [2] 3b 61 [2] 7c 70 [2] 32 7c [2] 3e 76 [2] 29 7d [2] 32 33 [2] 0f }

  condition:
    any of them
}