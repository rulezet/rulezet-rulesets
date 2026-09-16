rule TTP_XOR_MULT_DOSStub_256d {
  strings:
    $key_256d = { 71 05 [2] 05 1d [2] 42 1f [2] 05 0e [2] 4b 02 [2] 47 08 [2] 50 03 [2] 4b 4d [2] 76 }

  condition:
    any of them
}