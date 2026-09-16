rule TTP_XOR_MULT_DOSStub_3c4d {
  strings:
    $key_3c4d = { 68 25 [2] 1c 3d [2] 5b 3f [2] 1c 2e [2] 52 22 [2] 5e 28 [2] 49 23 [2] 52 6d [2] 6f }

  condition:
    any of them
}