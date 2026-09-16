rule TTP_XOR_MULT_DOSStub_357d {
  strings:
    $key_357d = { 61 15 [2] 15 0d [2] 52 0f [2] 15 1e [2] 5b 12 [2] 57 18 [2] 40 13 [2] 5b 5d [2] 66 }

  condition:
    any of them
}