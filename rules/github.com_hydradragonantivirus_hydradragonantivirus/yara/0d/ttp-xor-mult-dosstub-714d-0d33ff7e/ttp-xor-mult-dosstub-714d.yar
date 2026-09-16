rule TTP_XOR_MULT_DOSStub_714d {
  strings:
    $key_714d = { 25 25 [2] 51 3d [2] 16 3f [2] 51 2e [2] 1f 22 [2] 13 28 [2] 04 23 [2] 1f 6d [2] 22 }

  condition:
    any of them
}