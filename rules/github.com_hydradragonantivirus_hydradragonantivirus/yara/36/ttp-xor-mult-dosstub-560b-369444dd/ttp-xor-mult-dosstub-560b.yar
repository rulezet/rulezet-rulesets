rule TTP_XOR_MULT_DOSStub_560b {
  strings:
    $key_560b = { 02 63 [2] 76 7b [2] 31 79 [2] 76 68 [2] 38 64 [2] 34 6e [2] 23 65 [2] 38 2b [2] 05 }

  condition:
    any of them
}