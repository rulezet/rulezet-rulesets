rule TTP_XOR_MULT_DOSStub_3e4e {
  strings:
    $key_3e4e = { 6a 26 [2] 1e 3e [2] 59 3c [2] 1e 2d [2] 50 21 [2] 5c 2b [2] 4b 20 [2] 50 6e [2] 6d }

  condition:
    any of them
}