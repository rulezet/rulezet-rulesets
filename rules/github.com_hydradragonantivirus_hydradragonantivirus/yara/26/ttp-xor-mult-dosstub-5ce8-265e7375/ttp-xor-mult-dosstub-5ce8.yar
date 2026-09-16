rule TTP_XOR_MULT_DOSStub_5ce8 {
  strings:
    $key_5ce8 = { 08 80 [2] 7c 98 [2] 3b 9a [2] 7c 8b [2] 32 87 [2] 3e 8d [2] 29 86 [2] 32 c8 [2] 0f }

  condition:
    any of them
}