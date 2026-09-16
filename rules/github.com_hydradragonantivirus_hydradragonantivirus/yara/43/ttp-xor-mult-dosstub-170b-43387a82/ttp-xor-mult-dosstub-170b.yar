rule TTP_XOR_MULT_DOSStub_170b {
  strings:
    $key_170b = { 43 63 [2] 37 7b [2] 70 79 [2] 37 68 [2] 79 64 [2] 75 6e [2] 62 65 [2] 79 2b [2] 44 }

  condition:
    any of them
}