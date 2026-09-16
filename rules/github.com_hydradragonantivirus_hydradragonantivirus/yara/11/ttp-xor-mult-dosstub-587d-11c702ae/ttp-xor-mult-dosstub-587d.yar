rule TTP_XOR_MULT_DOSStub_587d {
  strings:
    $key_587d = { 0c 15 [2] 78 0d [2] 3f 0f [2] 78 1e [2] 36 12 [2] 3a 18 [2] 2d 13 [2] 36 5d [2] 0b }

  condition:
    any of them
}