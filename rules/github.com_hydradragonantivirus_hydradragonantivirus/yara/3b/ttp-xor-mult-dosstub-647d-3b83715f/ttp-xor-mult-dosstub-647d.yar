rule TTP_XOR_MULT_DOSStub_647d {
  strings:
    $key_647d = { 30 15 [2] 44 0d [2] 03 0f [2] 44 1e [2] 0a 12 [2] 06 18 [2] 11 13 [2] 0a 5d [2] 37 }

  condition:
    any of them
}