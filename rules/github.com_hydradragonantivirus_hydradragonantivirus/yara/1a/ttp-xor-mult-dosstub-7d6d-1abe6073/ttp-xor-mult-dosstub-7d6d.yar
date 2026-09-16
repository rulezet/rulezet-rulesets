rule TTP_XOR_MULT_DOSStub_7d6d {
  strings:
    $key_7d6d = { 29 05 [2] 5d 1d [2] 1a 1f [2] 5d 0e [2] 13 02 [2] 1f 08 [2] 08 03 [2] 13 4d [2] 2e }

  condition:
    any of them
}