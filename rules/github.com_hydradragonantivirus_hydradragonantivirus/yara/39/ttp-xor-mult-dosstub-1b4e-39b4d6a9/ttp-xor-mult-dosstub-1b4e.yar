rule TTP_XOR_MULT_DOSStub_1b4e {
  strings:
    $key_1b4e = { 4f 26 [2] 3b 3e [2] 7c 3c [2] 3b 2d [2] 75 21 [2] 79 2b [2] 6e 20 [2] 75 6e [2] 48 }

  condition:
    any of them
}