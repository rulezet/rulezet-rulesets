rule TTP_XOR_MULT_DOSStub_472d {
  strings:
    $key_472d = { 13 45 [2] 67 5d [2] 20 5f [2] 67 4e [2] 29 42 [2] 25 48 [2] 32 43 [2] 29 0d [2] 14 }

  condition:
    any of them
}