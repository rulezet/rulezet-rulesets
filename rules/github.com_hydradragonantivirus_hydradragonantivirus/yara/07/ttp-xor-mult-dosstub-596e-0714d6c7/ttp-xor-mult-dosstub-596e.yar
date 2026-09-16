rule TTP_XOR_MULT_DOSStub_596e {
  strings:
    $key_596e = { 0d 06 [2] 79 1e [2] 3e 1c [2] 79 0d [2] 37 01 [2] 3b 0b [2] 2c 00 [2] 37 4e [2] 0a }

  condition:
    any of them
}