rule TTP_XOR_MULT_DOSStub_4f4c {
  strings:
    $key_4f4c = { 1b 24 [2] 6f 3c [2] 28 3e [2] 6f 2f [2] 21 23 [2] 2d 29 [2] 3a 22 [2] 21 6c [2] 1c }

  condition:
    any of them
}