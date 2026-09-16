rule TTP_XOR_MULT_DOSStub_587c {
  strings:
    $key_587c = { 0c 14 [2] 78 0c [2] 3f 0e [2] 78 1f [2] 36 13 [2] 3a 19 [2] 2d 12 [2] 36 5c [2] 0b }

  condition:
    any of them
}