rule TTP_XOR_MULT_DOSStub_436e {
  strings:
    $key_436e = { 17 06 [2] 63 1e [2] 24 1c [2] 63 0d [2] 2d 01 [2] 21 0b [2] 36 00 [2] 2d 4e [2] 10 }

  condition:
    any of them
}