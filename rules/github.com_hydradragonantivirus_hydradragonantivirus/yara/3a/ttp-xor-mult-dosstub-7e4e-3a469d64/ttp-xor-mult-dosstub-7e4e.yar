rule TTP_XOR_MULT_DOSStub_7e4e {
  strings:
    $key_7e4e = { 2a 26 [2] 5e 3e [2] 19 3c [2] 5e 2d [2] 10 21 [2] 1c 2b [2] 0b 20 [2] 10 6e [2] 2d }

  condition:
    any of them
}