rule TTP_XOR_MULT_DOSStub_1e4e {
  strings:
    $key_1e4e = { 4a 26 [2] 3e 3e [2] 79 3c [2] 3e 2d [2] 70 21 [2] 7c 2b [2] 6b 20 [2] 70 6e [2] 4d }

  condition:
    any of them
}