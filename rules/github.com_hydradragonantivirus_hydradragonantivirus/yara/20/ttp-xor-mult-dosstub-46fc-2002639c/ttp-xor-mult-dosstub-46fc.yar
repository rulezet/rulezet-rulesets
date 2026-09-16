rule TTP_XOR_MULT_DOSStub_46fc {
  strings:
    $key_46fc = { 12 94 [2] 66 8c [2] 21 8e [2] 66 9f [2] 28 93 [2] 24 99 [2] 33 92 [2] 28 dc [2] 15 }

  condition:
    any of them
}