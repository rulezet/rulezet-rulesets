rule TTP_XOR_MULT_DOSStub_6afc {
  strings:
    $key_6afc = { 3e 94 [2] 4a 8c [2] 0d 8e [2] 4a 9f [2] 04 93 [2] 08 99 [2] 1f 92 [2] 04 dc [2] 39 }

  condition:
    any of them
}