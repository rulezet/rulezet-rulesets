rule TTP_XOR_MULT_DOSStub_7d2d {
  strings:
    $key_7d2d = { 29 45 [2] 5d 5d [2] 1a 5f [2] 5d 4e [2] 13 42 [2] 1f 48 [2] 08 43 [2] 13 0d [2] 2e }

  condition:
    any of them
}