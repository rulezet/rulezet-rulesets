rule TTP_XOR_MULT_DOSStub_060b {
  strings:
    $key_060b = { 52 63 [2] 26 7b [2] 61 79 [2] 26 68 [2] 68 64 [2] 64 6e [2] 73 65 [2] 68 2b [2] 55 }

  condition:
    any of them
}