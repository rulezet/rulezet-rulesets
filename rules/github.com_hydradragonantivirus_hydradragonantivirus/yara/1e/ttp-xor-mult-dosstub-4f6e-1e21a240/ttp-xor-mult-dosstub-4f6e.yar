rule TTP_XOR_MULT_DOSStub_4f6e {
  strings:
    $key_4f6e = { 1b 06 [2] 6f 1e [2] 28 1c [2] 6f 0d [2] 21 01 [2] 2d 0b [2] 3a 00 [2] 21 4e [2] 1c }

  condition:
    any of them
}