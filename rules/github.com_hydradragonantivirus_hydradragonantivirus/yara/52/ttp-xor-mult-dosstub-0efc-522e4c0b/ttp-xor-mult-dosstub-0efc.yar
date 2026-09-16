rule TTP_XOR_MULT_DOSStub_0efc {
  strings:
    $key_0efc = { 5a 94 [2] 2e 8c [2] 69 8e [2] 2e 9f [2] 60 93 [2] 6c 99 [2] 7b 92 [2] 60 dc [2] 5d }

  condition:
    any of them
}