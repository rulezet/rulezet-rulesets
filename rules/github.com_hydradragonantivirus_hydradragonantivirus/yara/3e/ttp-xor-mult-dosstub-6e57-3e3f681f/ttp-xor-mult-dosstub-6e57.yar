rule TTP_XOR_MULT_DOSStub_6e57 {
  strings:
    $key_6e57 = { 3a 3f [2] 4e 27 [2] 09 25 [2] 4e 34 [2] 00 38 [2] 0c 32 [2] 1b 39 [2] 00 77 [2] 3d }

  condition:
    any of them
}