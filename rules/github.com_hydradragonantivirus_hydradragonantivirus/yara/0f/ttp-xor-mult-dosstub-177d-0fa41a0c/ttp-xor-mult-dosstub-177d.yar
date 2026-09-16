rule TTP_XOR_MULT_DOSStub_177d {
  strings:
    $key_177d = { 43 15 [2] 37 0d [2] 70 0f [2] 37 1e [2] 79 12 [2] 75 18 [2] 62 13 [2] 79 5d [2] 44 }

  condition:
    any of them
}