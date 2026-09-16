rule TTP_XOR_MULT_DOSStub_622d {
  strings:
    $key_622d = { 36 45 [2] 42 5d [2] 05 5f [2] 42 4e [2] 0c 42 [2] 00 48 [2] 17 43 [2] 0c 0d [2] 31 }

  condition:
    any of them
}