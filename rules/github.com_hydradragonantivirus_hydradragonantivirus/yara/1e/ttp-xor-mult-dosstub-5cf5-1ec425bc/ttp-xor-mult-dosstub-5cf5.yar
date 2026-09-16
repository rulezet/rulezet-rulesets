rule TTP_XOR_MULT_DOSStub_5cf5 {
  strings:
    $key_5cf5 = { 08 9d [2] 7c 85 [2] 3b 87 [2] 7c 96 [2] 32 9a [2] 3e 90 [2] 29 9b [2] 32 d5 [2] 0f }

  condition:
    any of them
}