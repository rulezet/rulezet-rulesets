rule TTP_XOR_MULT_DOSStub_045d {
  strings:
    $key_045d = { 50 35 [2] 24 2d [2] 63 2f [2] 24 3e [2] 6a 32 [2] 66 38 [2] 71 33 [2] 6a 7d [2] 57 }

  condition:
    any of them
}