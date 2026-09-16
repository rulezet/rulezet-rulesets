rule TTP_XOR_MULT_DOSStub_7efc {
  strings:
    $key_7efc = { 2a 94 [2] 5e 8c [2] 19 8e [2] 5e 9f [2] 10 93 [2] 1c 99 [2] 0b 92 [2] 10 dc [2] 2d }

  condition:
    any of them
}