rule TTP_XOR_MULT_DOSStub_697b {
  strings:
    $key_697b = { 3d 13 [2] 49 0b [2] 0e 09 [2] 49 18 [2] 07 14 [2] 0b 1e [2] 1c 15 [2] 07 5b [2] 3a }

  condition:
    any of them
}