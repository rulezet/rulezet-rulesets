rule TTP_XOR_MULT_DOSStub_23fc {
  strings:
    $key_23fc = { 77 94 [2] 03 8c [2] 44 8e [2] 03 9f [2] 4d 93 [2] 41 99 [2] 56 92 [2] 4d dc [2] 70 }

  condition:
    any of them
}