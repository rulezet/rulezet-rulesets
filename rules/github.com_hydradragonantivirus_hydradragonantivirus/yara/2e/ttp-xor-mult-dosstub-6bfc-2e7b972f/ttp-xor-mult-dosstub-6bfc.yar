rule TTP_XOR_MULT_DOSStub_6bfc {
  strings:
    $key_6bfc = { 3f 94 [2] 4b 8c [2] 0c 8e [2] 4b 9f [2] 05 93 [2] 09 99 [2] 1e 92 [2] 05 dc [2] 38 }

  condition:
    any of them
}