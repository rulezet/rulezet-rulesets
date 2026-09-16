rule TTP_XOR_MULT_DOSStub_505d {
  strings:
    $key_505d = { 04 35 [2] 70 2d [2] 37 2f [2] 70 3e [2] 3e 32 [2] 32 38 [2] 25 33 [2] 3e 7d [2] 03 }

  condition:
    any of them
}