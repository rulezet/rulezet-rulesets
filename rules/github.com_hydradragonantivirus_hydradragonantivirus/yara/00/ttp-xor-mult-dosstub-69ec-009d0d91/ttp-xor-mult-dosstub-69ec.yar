rule TTP_XOR_MULT_DOSStub_69ec {
  strings:
    $key_69ec = { 3d 84 [2] 49 9c [2] 0e 9e [2] 49 8f [2] 07 83 [2] 0b 89 [2] 1c 82 [2] 07 cc [2] 3a }

  condition:
    any of them
}