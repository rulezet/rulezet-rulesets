rule TTP_XOR_MULT_DOSStub_7a7d {
  strings:
    $key_7a7d = { 2e 15 [2] 5a 0d [2] 1d 0f [2] 5a 1e [2] 14 12 [2] 18 18 [2] 0f 13 [2] 14 5d [2] 29 }

  condition:
    any of them
}