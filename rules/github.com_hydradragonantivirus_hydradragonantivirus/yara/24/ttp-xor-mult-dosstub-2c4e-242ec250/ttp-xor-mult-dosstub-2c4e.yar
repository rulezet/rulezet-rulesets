rule TTP_XOR_MULT_DOSStub_2c4e {
  strings:
    $key_2c4e = { 78 26 [2] 0c 3e [2] 4b 3c [2] 0c 2d [2] 42 21 [2] 4e 2b [2] 59 20 [2] 42 6e [2] 7f }

  condition:
    any of them
}