rule TTP_XOR_MULT_DOSStub_360b {
  strings:
    $key_360b = { 62 63 [2] 16 7b [2] 51 79 [2] 16 68 [2] 58 64 [2] 54 6e [2] 43 65 [2] 58 2b [2] 65 }

  condition:
    any of them
}