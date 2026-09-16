rule TTP_XOR_MULT_DOSStub_6e1a {
  strings:
    $key_6e1a = { 3a 72 [2] 4e 6a [2] 09 68 [2] 4e 79 [2] 00 75 [2] 0c 7f [2] 1b 74 [2] 00 3a [2] 3d }

  condition:
    any of them
}