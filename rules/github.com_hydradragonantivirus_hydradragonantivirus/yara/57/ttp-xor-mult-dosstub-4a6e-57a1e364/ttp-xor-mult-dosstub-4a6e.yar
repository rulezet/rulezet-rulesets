rule TTP_XOR_MULT_DOSStub_4a6e {
  strings:
    $key_4a6e = { 1e 06 [2] 6a 1e [2] 2d 1c [2] 6a 0d [2] 24 01 [2] 28 0b [2] 3f 00 [2] 24 4e [2] 19 }

  condition:
    any of them
}