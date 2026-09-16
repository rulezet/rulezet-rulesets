rule TTP_XOR_MULT_DOSStub_160d {
  strings:
    $key_160d = { 42 65 [2] 36 7d [2] 71 7f [2] 36 6e [2] 78 62 [2] 74 68 [2] 63 63 [2] 78 2d [2] 45 }

  condition:
    any of them
}