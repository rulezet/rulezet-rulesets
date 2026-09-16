rule TTP_XOR_MULT_DOSStub_6e1b {
  strings:
    $key_6e1b = { 3a 73 [2] 4e 6b [2] 09 69 [2] 4e 78 [2] 00 74 [2] 0c 7e [2] 1b 75 [2] 00 3b [2] 3d }

  condition:
    any of them
}