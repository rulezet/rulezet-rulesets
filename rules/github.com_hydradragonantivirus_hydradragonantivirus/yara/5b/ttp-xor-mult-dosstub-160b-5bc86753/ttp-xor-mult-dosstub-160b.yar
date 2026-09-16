rule TTP_XOR_MULT_DOSStub_160b {
  strings:
    $key_160b = { 42 63 [2] 36 7b [2] 71 79 [2] 36 68 [2] 78 64 [2] 74 6e [2] 63 65 [2] 78 2b [2] 45 }

  condition:
    any of them
}