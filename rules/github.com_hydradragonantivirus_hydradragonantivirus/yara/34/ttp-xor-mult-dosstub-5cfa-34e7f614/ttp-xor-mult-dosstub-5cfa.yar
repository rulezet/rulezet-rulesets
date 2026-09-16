rule TTP_XOR_MULT_DOSStub_5cfa {
  strings:
    $key_5cfa = { 08 92 [2] 7c 8a [2] 3b 88 [2] 7c 99 [2] 32 95 [2] 3e 9f [2] 29 94 [2] 32 da [2] 0f }

  condition:
    any of them
}