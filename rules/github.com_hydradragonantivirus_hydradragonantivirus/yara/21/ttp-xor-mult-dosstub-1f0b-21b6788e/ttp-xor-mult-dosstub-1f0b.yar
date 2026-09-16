rule TTP_XOR_MULT_DOSStub_1f0b {
  strings:
    $key_1f0b = { 4b 63 [2] 3f 7b [2] 78 79 [2] 3f 68 [2] 71 64 [2] 7d 6e [2] 6a 65 [2] 71 2b [2] 4c }

  condition:
    any of them
}