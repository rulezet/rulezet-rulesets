rule TTP_XOR_MULT_DOSStub_76fc {
  strings:
    $key_76fc = { 22 94 [2] 56 8c [2] 11 8e [2] 56 9f [2] 18 93 [2] 14 99 [2] 03 92 [2] 18 dc [2] 25 }

  condition:
    any of them
}