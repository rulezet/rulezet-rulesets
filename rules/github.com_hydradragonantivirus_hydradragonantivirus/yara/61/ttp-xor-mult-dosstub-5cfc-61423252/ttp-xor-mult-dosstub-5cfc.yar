rule TTP_XOR_MULT_DOSStub_5cfc {
  strings:
    $key_5cfc = { 08 94 [2] 7c 8c [2] 3b 8e [2] 7c 9f [2] 32 93 [2] 3e 99 [2] 29 92 [2] 32 dc [2] 0f }

  condition:
    any of them
}