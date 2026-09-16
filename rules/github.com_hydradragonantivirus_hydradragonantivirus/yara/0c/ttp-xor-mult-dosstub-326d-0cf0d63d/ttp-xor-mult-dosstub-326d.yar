rule TTP_XOR_MULT_DOSStub_326d {
  strings:
    $key_326d = { 66 05 [2] 12 1d [2] 55 1f [2] 12 0e [2] 5c 02 [2] 50 08 [2] 47 03 [2] 5c 4d [2] 61 }

  condition:
    any of them
}