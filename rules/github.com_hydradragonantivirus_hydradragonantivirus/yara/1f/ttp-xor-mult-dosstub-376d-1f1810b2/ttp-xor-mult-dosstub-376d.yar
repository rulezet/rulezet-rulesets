rule TTP_XOR_MULT_DOSStub_376d {
  strings:
    $key_376d = { 63 05 [2] 17 1d [2] 50 1f [2] 17 0e [2] 59 02 [2] 55 08 [2] 42 03 [2] 59 4d [2] 64 }

  condition:
    any of them
}