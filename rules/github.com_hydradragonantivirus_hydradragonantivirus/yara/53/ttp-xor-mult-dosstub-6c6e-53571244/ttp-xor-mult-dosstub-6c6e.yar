rule TTP_XOR_MULT_DOSStub_6c6e {
  strings:
    $key_6c6e = { 38 06 [2] 4c 1e [2] 0b 1c [2] 4c 0d [2] 02 01 [2] 0e 0b [2] 19 00 [2] 02 4e [2] 3f }

  condition:
    any of them
}