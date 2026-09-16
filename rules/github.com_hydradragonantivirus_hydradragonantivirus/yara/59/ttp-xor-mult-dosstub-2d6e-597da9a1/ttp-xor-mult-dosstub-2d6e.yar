rule TTP_XOR_MULT_DOSStub_2d6e {
  strings:
    $key_2d6e = { 79 06 [2] 0d 1e [2] 4a 1c [2] 0d 0d [2] 43 01 [2] 4f 0b [2] 58 00 [2] 43 4e [2] 7e }

  condition:
    any of them
}