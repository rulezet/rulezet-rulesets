rule TTP_XOR_MULT_DOSStub_7d5d {
  strings:
    $key_7d5d = { 29 35 [2] 5d 2d [2] 1a 2f [2] 5d 3e [2] 13 32 [2] 1f 38 [2] 08 33 [2] 13 7d [2] 2e }

  condition:
    any of them
}