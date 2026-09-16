rule TTP_XOR_MULT_DOSStub_525d {
  strings:
    $key_525d = { 06 35 [2] 72 2d [2] 35 2f [2] 72 3e [2] 3c 32 [2] 30 38 [2] 27 33 [2] 3c 7d [2] 01 }

  condition:
    any of them
}