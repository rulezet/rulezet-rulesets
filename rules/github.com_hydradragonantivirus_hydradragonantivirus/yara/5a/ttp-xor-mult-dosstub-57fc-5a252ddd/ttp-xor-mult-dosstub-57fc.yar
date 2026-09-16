rule TTP_XOR_MULT_DOSStub_57fc {
  strings:
    $key_57fc = { 03 94 [2] 77 8c [2] 30 8e [2] 77 9f [2] 39 93 [2] 35 99 [2] 22 92 [2] 39 dc [2] 04 }

  condition:
    any of them
}