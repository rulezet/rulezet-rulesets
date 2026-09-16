rule TTP_XOR_MULT_DOSStub_796e {
  strings:
    $key_796e = { 2d 06 [2] 59 1e [2] 1e 1c [2] 59 0d [2] 17 01 [2] 1b 0b [2] 0c 00 [2] 17 4e [2] 2a }

  condition:
    any of them
}