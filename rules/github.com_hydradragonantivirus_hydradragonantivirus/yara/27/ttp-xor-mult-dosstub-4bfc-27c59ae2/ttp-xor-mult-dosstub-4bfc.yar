rule TTP_XOR_MULT_DOSStub_4bfc {
  strings:
    $key_4bfc = { 1f 94 [2] 6b 8c [2] 2c 8e [2] 6b 9f [2] 25 93 [2] 29 99 [2] 3e 92 [2] 25 dc [2] 18 }

  condition:
    any of them
}