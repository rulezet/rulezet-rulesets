rule TTP_XOR_MULT_DOSStub_67fc {
  strings:
    $key_67fc = { 33 94 [2] 47 8c [2] 00 8e [2] 47 9f [2] 09 93 [2] 05 99 [2] 12 92 [2] 09 dc [2] 34 }

  condition:
    any of them
}