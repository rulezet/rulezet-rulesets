rule TTP_XOR_MULT_DOSStub_130b {
  strings:
    $key_130b = { 47 63 [2] 33 7b [2] 74 79 [2] 33 68 [2] 7d 64 [2] 71 6e [2] 66 65 [2] 7d 2b [2] 40 }

  condition:
    any of them
}