rule TTP_XOR_MULT_DOSStub_37fc {
  strings:
    $key_37fc = { 63 94 [2] 17 8c [2] 50 8e [2] 17 9f [2] 59 93 [2] 55 99 [2] 42 92 [2] 59 dc [2] 64 }

  condition:
    any of them
}