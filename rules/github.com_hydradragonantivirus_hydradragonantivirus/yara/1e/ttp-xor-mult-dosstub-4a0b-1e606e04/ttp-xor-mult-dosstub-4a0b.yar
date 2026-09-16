rule TTP_XOR_MULT_DOSStub_4a0b {
  strings:
    $key_4a0b = { 1e 63 [2] 6a 7b [2] 2d 79 [2] 6a 68 [2] 24 64 [2] 28 6e [2] 3f 65 [2] 24 2b [2] 19 }

  condition:
    any of them
}