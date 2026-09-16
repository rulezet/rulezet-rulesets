rule TTP_XOR_MULT_DOSStub_7dfc {
  strings:
    $key_7dfc = { 29 94 [2] 5d 8c [2] 1a 8e [2] 5d 9f [2] 13 93 [2] 1f 99 [2] 08 92 [2] 13 dc [2] 2e }

  condition:
    any of them
}