rule TTP_XOR_MULT_DOSStub_440b {
  strings:
    $key_440b = { 10 63 [2] 64 7b [2] 23 79 [2] 64 68 [2] 2a 64 [2] 26 6e [2] 31 65 [2] 2a 2b [2] 17 }

  condition:
    any of them
}