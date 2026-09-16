rule TTP_XOR_MULT_DOSStub_064d {
  strings:
    $key_064d = { 52 25 [2] 26 3d [2] 61 3f [2] 26 2e [2] 68 22 [2] 64 28 [2] 73 23 [2] 68 6d [2] 55 }

  condition:
    any of them
}