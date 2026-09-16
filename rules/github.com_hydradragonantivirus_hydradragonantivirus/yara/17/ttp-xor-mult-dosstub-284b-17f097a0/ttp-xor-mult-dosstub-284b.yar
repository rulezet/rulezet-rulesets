rule TTP_XOR_MULT_DOSStub_284b {
  strings:
    $key_284b = { 7c 23 [2] 08 3b [2] 4f 39 [2] 08 28 [2] 46 24 [2] 4a 2e [2] 5d 25 [2] 46 6b [2] 7b }

  condition:
    any of them
}