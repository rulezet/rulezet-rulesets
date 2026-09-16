rule TTP_XOR_MULT_DOSStub_7b4d {
  strings:
    $key_7b4d = { 2f 25 [2] 5b 3d [2] 1c 3f [2] 5b 2e [2] 15 22 [2] 19 28 [2] 0e 23 [2] 15 6d [2] 28 }

  condition:
    any of them
}