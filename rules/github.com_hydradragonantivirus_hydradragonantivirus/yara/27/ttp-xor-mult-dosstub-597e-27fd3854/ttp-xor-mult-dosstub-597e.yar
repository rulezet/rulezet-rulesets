rule TTP_XOR_MULT_DOSStub_597e {
  strings:
    $key_597e = { 0d 16 [2] 79 0e [2] 3e 0c [2] 79 1d [2] 37 11 [2] 3b 1b [2] 2c 10 [2] 37 5e [2] 0a }

  condition:
    any of them
}