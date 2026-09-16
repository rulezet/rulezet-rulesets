rule TTP_XOR_MULT_DOSStub_584c {
  strings:
    $key_584c = { 0c 24 [2] 78 3c [2] 3f 3e [2] 78 2f [2] 36 23 [2] 3a 29 [2] 2d 22 [2] 36 6c [2] 0b }

  condition:
    any of them
}