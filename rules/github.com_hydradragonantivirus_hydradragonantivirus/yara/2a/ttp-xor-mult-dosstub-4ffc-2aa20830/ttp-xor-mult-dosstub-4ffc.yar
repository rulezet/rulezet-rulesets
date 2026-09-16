rule TTP_XOR_MULT_DOSStub_4ffc {
  strings:
    $key_4ffc = { 1b 94 [2] 6f 8c [2] 28 8e [2] 6f 9f [2] 21 93 [2] 2d 99 [2] 3a 92 [2] 21 dc [2] 1c }

  condition:
    any of them
}