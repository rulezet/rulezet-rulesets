rule TTP_XOR_MULT_DOSStub_035d {
  strings:
    $key_035d = { 57 35 [2] 23 2d [2] 64 2f [2] 23 3e [2] 6d 32 [2] 61 38 [2] 76 33 [2] 6d 7d [2] 50 }

  condition:
    any of them
}