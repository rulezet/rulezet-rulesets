rule TTP_XOR_MULT_DOSStub_530b {
  strings:
    $key_530b = { 07 63 [2] 73 7b [2] 34 79 [2] 73 68 [2] 3d 64 [2] 31 6e [2] 26 65 [2] 3d 2b [2] 00 }

  condition:
    any of them
}