rule TTP_XOR_MULT_DOSStub_0e4d {
  strings:
    $key_0e4d = { 5a 25 [2] 2e 3d [2] 69 3f [2] 2e 2e [2] 60 22 [2] 6c 28 [2] 7b 23 [2] 60 6d [2] 5d }

  condition:
    any of them
}