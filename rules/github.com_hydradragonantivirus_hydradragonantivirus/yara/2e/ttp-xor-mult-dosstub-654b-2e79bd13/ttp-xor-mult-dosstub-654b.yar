rule TTP_XOR_MULT_DOSStub_654b {
  strings:
    $key_654b = { 31 23 [2] 45 3b [2] 02 39 [2] 45 28 [2] 0b 24 [2] 07 2e [2] 10 25 [2] 0b 6b [2] 36 }

  condition:
    any of them
}