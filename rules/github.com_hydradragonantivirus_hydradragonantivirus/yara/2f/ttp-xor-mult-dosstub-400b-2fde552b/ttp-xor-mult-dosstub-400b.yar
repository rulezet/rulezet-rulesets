rule TTP_XOR_MULT_DOSStub_400b {
  strings:
    $key_400b = { 14 63 [2] 60 7b [2] 27 79 [2] 60 68 [2] 2e 64 [2] 22 6e [2] 35 65 [2] 2e 2b [2] 13 }

  condition:
    any of them
}