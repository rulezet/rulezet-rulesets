rule TTP_XOR_MULT_DOSStub_781b {
  strings:
    $key_781b = { 2c 73 [2] 58 6b [2] 1f 69 [2] 58 78 [2] 16 74 [2] 1a 7e [2] 0d 75 [2] 16 3b [2] 2b }

  condition:
    any of them
}