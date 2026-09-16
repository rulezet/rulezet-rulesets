rule TTP_XOR_MULT_DOSStub_555d {
  strings:
    $key_555d = { 01 35 [2] 75 2d [2] 32 2f [2] 75 3e [2] 3b 32 [2] 37 38 [2] 20 33 [2] 3b 7d [2] 06 }

  condition:
    any of them
}