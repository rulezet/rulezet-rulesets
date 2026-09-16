rule TTP_XOR_MULT_DOSStub_1efc {
  strings:
    $key_1efc = { 4a 94 [2] 3e 8c [2] 79 8e [2] 3e 9f [2] 70 93 [2] 7c 99 [2] 6b 92 [2] 70 dc [2] 4d }

  condition:
    any of them
}