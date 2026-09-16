rule TTP_XOR_MULT_DOSStub_2cfc {
  strings:
    $key_2cfc = { 78 94 [2] 0c 8c [2] 4b 8e [2] 0c 9f [2] 42 93 [2] 4e 99 [2] 59 92 [2] 42 dc [2] 7f }

  condition:
    any of them
}