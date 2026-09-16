rule TTP_XOR_MULT_DOSStub_5e4e {
  strings:
    $key_5e4e = { 0a 26 [2] 7e 3e [2] 39 3c [2] 7e 2d [2] 30 21 [2] 3c 2b [2] 2b 20 [2] 30 6e [2] 0d }

  condition:
    any of them
}