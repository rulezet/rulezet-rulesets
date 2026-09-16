rule TTP_XOR_MULT_DOSStub_047d {
  strings:
    $key_047d = { 50 15 [2] 24 0d [2] 63 0f [2] 24 1e [2] 6a 12 [2] 66 18 [2] 71 13 [2] 6a 5d [2] 57 }

  condition:
    any of them
}