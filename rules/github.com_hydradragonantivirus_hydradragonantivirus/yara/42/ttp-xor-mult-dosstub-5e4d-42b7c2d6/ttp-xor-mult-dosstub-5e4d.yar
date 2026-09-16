rule TTP_XOR_MULT_DOSStub_5e4d {
  strings:
    $key_5e4d = { 0a 25 [2] 7e 3d [2] 39 3f [2] 7e 2e [2] 30 22 [2] 3c 28 [2] 2b 23 [2] 30 6d [2] 0d }

  condition:
    any of them
}