rule TTP_XOR_MULT_DOSStub_581b {
  strings:
    $key_581b = { 0c 73 [2] 78 6b [2] 3f 69 [2] 78 78 [2] 36 74 [2] 3a 7e [2] 2d 75 [2] 36 3b [2] 0b }

  condition:
    any of them
}