rule TTP_XOR_MULT_DOSStub_204e {
  strings:
    $key_204e = { 74 26 [2] 00 3e [2] 47 3c [2] 00 2d [2] 4e 21 [2] 42 2b [2] 55 20 [2] 4e 6e [2] 73 }

  condition:
    any of them
}