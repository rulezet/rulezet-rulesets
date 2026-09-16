rule TTP_XOR_MULT_DOSStub_58ec {
  strings:
    $key_58ec = { 0c 84 [2] 78 9c [2] 3f 9e [2] 78 8f [2] 36 83 [2] 3a 89 [2] 2d 82 [2] 36 cc [2] 0b }

  condition:
    any of them
}