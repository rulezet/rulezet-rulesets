rule TTP_XOR_MULT_DOSStub_3e4d {
  strings:
    $key_3e4d = { 6a 25 [2] 1e 3d [2] 59 3f [2] 1e 2e [2] 50 22 [2] 5c 28 [2] 4b 23 [2] 50 6d [2] 6d }

  condition:
    any of them
}