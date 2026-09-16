rule TTP_XOR_MULT_DOSStub_7d7d {
  strings:
    $key_7d7d = { 29 15 [2] 5d 0d [2] 1a 0f [2] 5d 1e [2] 13 12 [2] 1f 18 [2] 08 13 [2] 13 5d [2] 2e }

  condition:
    any of them
}