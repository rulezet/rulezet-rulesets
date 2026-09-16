rule TTP_XOR_MULT_DOSStub_767d {
  strings:
    $key_767d = { 22 15 [2] 56 0d [2] 11 0f [2] 56 1e [2] 18 12 [2] 14 18 [2] 03 13 [2] 18 5d [2] 25 }

  condition:
    any of them
}