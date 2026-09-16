rule TTP_XOR_MULT_DOSStub_5efc {
  strings:
    $key_5efc = { 0a 94 [2] 7e 8c [2] 39 8e [2] 7e 9f [2] 30 93 [2] 3c 99 [2] 2b 92 [2] 30 dc [2] 0d }

  condition:
    any of them
}