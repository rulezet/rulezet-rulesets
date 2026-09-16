rule TTP_XOR_MULT_DOSStub_357e {
  strings:
    $key_357e = { 61 16 [2] 15 0e [2] 52 0c [2] 15 1d [2] 5b 11 [2] 57 1b [2] 40 10 [2] 5b 5e [2] 66 }

  condition:
    any of them
}