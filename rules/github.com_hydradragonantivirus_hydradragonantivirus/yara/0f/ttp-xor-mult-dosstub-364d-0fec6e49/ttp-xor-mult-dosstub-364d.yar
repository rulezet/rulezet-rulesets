rule TTP_XOR_MULT_DOSStub_364d {
  strings:
    $key_364d = { 62 25 [2] 16 3d [2] 51 3f [2] 16 2e [2] 58 22 [2] 54 28 [2] 43 23 [2] 58 6d [2] 65 }

  condition:
    any of them
}