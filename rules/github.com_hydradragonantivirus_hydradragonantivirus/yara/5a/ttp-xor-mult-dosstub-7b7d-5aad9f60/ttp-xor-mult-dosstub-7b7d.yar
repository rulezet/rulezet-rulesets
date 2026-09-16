rule TTP_XOR_MULT_DOSStub_7b7d {
  strings:
    $key_7b7d = { 2f 15 [2] 5b 0d [2] 1c 0f [2] 5b 1e [2] 15 12 [2] 19 18 [2] 0e 13 [2] 15 5d [2] 28 }

  condition:
    any of them
}