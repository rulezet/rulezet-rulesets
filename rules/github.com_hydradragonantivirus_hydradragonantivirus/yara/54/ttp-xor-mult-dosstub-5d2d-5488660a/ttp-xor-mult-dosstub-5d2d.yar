rule TTP_XOR_MULT_DOSStub_5d2d {
  strings:
    $key_5d2d = { 09 45 [2] 7d 5d [2] 3a 5f [2] 7d 4e [2] 33 42 [2] 3f 48 [2] 28 43 [2] 33 0d [2] 0e }

  condition:
    any of them
}