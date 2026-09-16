rule TTP_XOR_MULT_DOSStub_7cfc {
  strings:
    $key_7cfc = { 28 94 [2] 5c 8c [2] 1b 8e [2] 5c 9f [2] 12 93 [2] 1e 99 [2] 09 92 [2] 12 dc [2] 2f }

  condition:
    any of them
}