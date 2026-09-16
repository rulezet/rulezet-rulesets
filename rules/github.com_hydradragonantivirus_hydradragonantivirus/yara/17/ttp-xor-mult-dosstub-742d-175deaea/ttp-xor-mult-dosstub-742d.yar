rule TTP_XOR_MULT_DOSStub_742d {
  strings:
    $key_742d = { 20 45 [2] 54 5d [2] 13 5f [2] 54 4e [2] 1a 42 [2] 16 48 [2] 01 43 [2] 1a 0d [2] 27 }

  condition:
    any of them
}