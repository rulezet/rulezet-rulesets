rule TTP_XOR_MULT_DOSStub_6e26 {
  strings:
    $key_6e26 = { 3a 4e [2] 4e 56 [2] 09 54 [2] 4e 45 [2] 00 49 [2] 0c 43 [2] 1b 48 [2] 00 06 [2] 3d }

  condition:
    any of them
}