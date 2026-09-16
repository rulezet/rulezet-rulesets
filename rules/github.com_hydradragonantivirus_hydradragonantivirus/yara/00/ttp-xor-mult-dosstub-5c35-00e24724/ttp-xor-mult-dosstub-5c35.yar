rule TTP_XOR_MULT_DOSStub_5c35 {
  strings:
    $key_5c35 = { 08 5d [2] 7c 45 [2] 3b 47 [2] 7c 56 [2] 32 5a [2] 3e 50 [2] 29 5b [2] 32 15 [2] 0f }

  condition:
    any of them
}