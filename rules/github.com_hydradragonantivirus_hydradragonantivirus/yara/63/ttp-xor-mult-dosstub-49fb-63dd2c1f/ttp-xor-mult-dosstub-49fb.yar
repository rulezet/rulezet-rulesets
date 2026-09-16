rule TTP_XOR_MULT_DOSStub_49fb {
  strings:
    $key_49fb = { 1d 93 [2] 69 8b [2] 2e 89 [2] 69 98 [2] 27 94 [2] 2b 9e [2] 3c 95 [2] 27 db [2] 1a }

  condition:
    any of them
}