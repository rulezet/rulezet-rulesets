rule TTP_XOR_MULT_DOSStub_7d4e {
  strings:
    $key_7d4e = { 29 26 [2] 5d 3e [2] 1a 3c [2] 5d 2d [2] 13 21 [2] 1f 2b [2] 08 20 [2] 13 6e [2] 2e }

  condition:
    any of them
}