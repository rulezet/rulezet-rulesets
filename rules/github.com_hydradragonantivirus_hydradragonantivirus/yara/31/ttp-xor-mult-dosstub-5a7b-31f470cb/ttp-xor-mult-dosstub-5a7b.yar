rule TTP_XOR_MULT_DOSStub_5a7b {
  strings:
    $key_5a7b = { 0e 13 [2] 7a 0b [2] 3d 09 [2] 7a 18 [2] 34 14 [2] 38 1e [2] 2f 15 [2] 34 5b [2] 09 }

  condition:
    any of them
}