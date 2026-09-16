rule TTP_XOR_MULT_DOSStub_635d {
  strings:
    $key_635d = { 37 35 [2] 43 2d [2] 04 2f [2] 43 3e [2] 0d 32 [2] 01 38 [2] 16 33 [2] 0d 7d [2] 30 }

  condition:
    any of them
}