rule TTP_XOR_MULT_DOSStub_6c4e {
  strings:
    $key_6c4e = { 38 26 [2] 4c 3e [2] 0b 3c [2] 4c 2d [2] 02 21 [2] 0e 2b [2] 19 20 [2] 02 6e [2] 3f }

  condition:
    any of them
}