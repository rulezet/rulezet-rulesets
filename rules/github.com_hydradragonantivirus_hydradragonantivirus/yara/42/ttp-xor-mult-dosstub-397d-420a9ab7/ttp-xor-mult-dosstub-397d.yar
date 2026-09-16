rule TTP_XOR_MULT_DOSStub_397d {
  strings:
    $key_397d = { 6d 15 [2] 19 0d [2] 5e 0f [2] 19 1e [2] 57 12 [2] 5b 18 [2] 4c 13 [2] 57 5d [2] 6a }

  condition:
    any of them
}