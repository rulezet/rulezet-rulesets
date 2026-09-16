rule TTP_XOR_MULT_DOSStub_5d7d {
  strings:
    $key_5d7d = { 09 15 [2] 7d 0d [2] 3a 0f [2] 7d 1e [2] 33 12 [2] 3f 18 [2] 28 13 [2] 33 5d [2] 0e }

  condition:
    any of them
}