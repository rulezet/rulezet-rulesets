rule TTP_XOR_MULT_DOSStub_4dfc {
  strings:
    $key_4dfc = { 19 94 [2] 6d 8c [2] 2a 8e [2] 6d 9f [2] 23 93 [2] 2f 99 [2] 38 92 [2] 23 dc [2] 1e }

  condition:
    any of them
}