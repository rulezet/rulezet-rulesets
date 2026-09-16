rule TTP_XOR_MULT_DOSStub_580b {
  strings:
    $key_580b = { 0c 63 [2] 78 7b [2] 3f 79 [2] 78 68 [2] 36 64 [2] 3a 6e [2] 2d 65 [2] 36 2b [2] 0b }

  condition:
    any of them
}